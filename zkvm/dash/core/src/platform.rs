//! Platform facts read with Drive's own verifiers (dashpay/platform v4.1.1): a DPNS
//! `domain` document resolving a username, and the full identity it points to.

use crate::error::Error;
use crate::chain::Hash;
use dpp::data_contract::accessors::v0::DataContractV0Getters;
use dpp::document::DocumentV0Getters;
use dpp::identity::accessors::IdentityGettersV0;
use dpp::identity::identity_public_key::accessors::v0::IdentityPublicKeyGettersV0;
use dpp::identity::KeyType;
use dpp::platform_value::Value;
use dpp::system_data_contracts::{load_system_data_contract, SystemDataContract};
use dpp::version::PlatformVersion;
use drive::config::DriveConfig;
use drive::drive::Drive;
use drive::query::DriveDocumentQuery;

pub const DPNS_PARENT: &str = "dash";

pub struct Key {
    pub id: u32,
    pub purpose: u8,
    pub security_level: u8,
    pub eth_address: [u8; 20],
}

pub struct Username {
    pub app_hash: Hash,
    pub label: String,
    pub normalized_label: String,
    pub identity_id: Hash,
}

pub struct IdentityFacts {
    pub app_hash: Hash,
    pub balance: u64,
    pub revision: u64,
    pub keys: Vec<Key>,
}

fn text(v: Option<&Value>) -> Result<String, Error> {
    match v {
        Some(Value::Text(s)) => Ok(s.clone()),
        _ => Err(Error::BadDocument),
    }
}

/// Verify the proof of `getDocuments(dpns, domain, normalizedParentDomainName == "dash" &&
/// normalizedLabel == label, limit 1)` and return the single matching domain.
pub fn verify_username(
    proof: &[u8],
    normalized_label: &str,
    pv: &PlatformVersion,
) -> Result<Username, Error> {
    let contract = load_system_data_contract(SystemDataContract::DPNS, pv).map_err(|_| Error::Drive)?;
    let doc_type = contract.document_type_for_name("domain").map_err(|_| Error::Drive)?;
    let where_clause = Value::Array(vec![
        Value::Array(vec![
            Value::Text("normalizedParentDomainName".into()),
            Value::Text("==".into()),
            Value::Text(DPNS_PARENT.into()),
        ]),
        Value::Array(vec![
            Value::Text("normalizedLabel".into()),
            Value::Text("==".into()),
            Value::Text(normalized_label.into()),
        ]),
    ]);
    let query = DriveDocumentQuery::from_decomposed_values(
        where_clause,
        None,
        Some(1),
        None,
        false,
        None,
        &contract,
        doc_type,
        &DriveConfig::default(),
    )
    .map_err(|_| Error::Drive)?;
    let (root, docs) = query.verify_proof(proof, pv).map_err(|_| Error::Drive)?;
    let [doc] = docs.as_slice() else {
        return Err(Error::NameNotFound);
    };
    let props = doc.properties();
    if text(props.get("normalizedParentDomainName"))? != DPNS_PARENT
        || text(props.get("normalizedLabel"))? != normalized_label
    {
        return Err(Error::BadDocument);
    }
    let identity = match props.get("records") {
        Some(Value::Map(m)) => m
            .iter()
            .find(|(k, _)| matches!(k, Value::Text(t) if t == "identity"))
            .map(|(_, v)| v.clone()),
        _ => None,
    };
    let identity_id: Hash = match identity {
        Some(Value::Identifier(id)) => id,
        Some(Value::Bytes32(id)) => id,
        _ => return Err(Error::BadDocument),
    };
    Ok(Username {
        app_hash: root,
        label: text(props.get("label"))?,
        normalized_label: normalized_label.to_string(),
        identity_id,
    })
}

fn eth_address(compressed: &[u8]) -> Result<[u8; 20], Error> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    let pk = k256::PublicKey::from_sec1_bytes(compressed).map_err(|_| Error::BadKey)?;
    let p = pk.to_encoded_point(false);
    let mut h = [0u8; 32];
    let mut k = tiny_keccak::Keccak::v256();
    tiny_keccak::Hasher::update(&mut k, &p.as_bytes()[1..]);
    tiny_keccak::Hasher::finalize(k, &mut h);
    Ok(h[12..].try_into().unwrap())
}

/// Verify the proof of `getIdentity(identity_id)` and return its balance, revision and its
/// enabled secp256k1 keys as Ethereum addresses.
pub fn verify_identity(proof: &[u8], identity_id: Hash, pv: &PlatformVersion) -> Result<IdentityFacts, Error> {
    let (root, identity) =
        Drive::verify_full_identity_by_identity_id(proof, false, identity_id, pv).map_err(|_| Error::Drive)?;
    let identity = identity.ok_or(Error::IdentityNotFound)?;
    if identity.id().to_buffer() != identity_id {
        return Err(Error::IdentityNotFound);
    }
    let mut keys = Vec::new();
    for (id, key) in identity.public_keys() {
        if key.key_type() != KeyType::ECDSA_SECP256K1 || key.disabled_at().is_some() {
            continue;
        }
        keys.push(Key {
            id: *id,
            purpose: key.purpose() as u8,
            security_level: key.security_level() as u8,
            eth_address: eth_address(key.data().as_slice())?,
        });
    }
    Ok(IdentityFacts {
        app_hash: root,
        balance: identity.balance(),
        revision: identity.revision(),
        keys,
    })
}
