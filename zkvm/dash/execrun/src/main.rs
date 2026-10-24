//! Native run of the Dash username guest logic over an input JSON (tools/build_input.py):
//! prints the statement, writes the ABI public values and the bincode SP1 stdin blob.

use dash_lane_core::chain::Hash;
use dash_lane_core::{ChainLockStep, CoreBlock, Input, PlatformCommit, QuorumWitness};
use serde_json::Value;

fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string")).expect("hex")
}
fn hash(v: &Value) -> Hash {
    bytes(v).try_into().expect("32 bytes")
}
fn hashes(v: &Value) -> Vec<Hash> {
    v.as_array().expect("array").iter().map(hash).collect()
}
fn block(v: &Value) -> CoreBlock {
    CoreBlock {
        header: bytes(&v["header"]),
        coinbase: bytes(&v["coinbase"]),
        coinbase_branch: hashes(&v["coinbase_branch"]),
    }
}
fn quorum(v: &Value) -> QuorumWitness {
    QuorumWitness {
        commitment: bytes(&v["commitment"]),
        branch: hashes(&v["branch"]),
        index: v["index"].as_u64().unwrap() as u32,
    }
}

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: dash-execrun <input.json>");
    let j: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let c = &j["commit"];
    let input = Input {
        start: block(&j["start"]),
        steps: j["steps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| ChainLockStep {
                block: block(&s["block"]),
                signature: bytes(&s["signature"]),
                signer: quorum(&s["signer"]),
            })
            .collect(),
        platform_block: block(&j["platform_block"]),
        link_headers: j["link_headers"]
            .as_array()
            .unwrap()
            .iter()
            .map(bytes)
            .collect(),
        platform_quorum: quorum(&j["platform_quorum"]),
        commit: PlatformCommit {
            height: c["height"].as_u64().unwrap(),
            core_chain_locked_height: c["core_chain_locked_height"].as_u64().unwrap() as u32,
            time_ms: c["time_ms"].as_u64().unwrap(),
            protocol_version: c["protocol_version"].as_u64().unwrap() as u32,
            chain_id: c["chain_id"].as_str().unwrap().to_string(),
            round: c["round"].as_u64().unwrap() as u32,
            block_id_hash: hash(&c["block_id_hash"]),
            quorum_type: c["quorum_type"].as_u64().unwrap() as u32,
            quorum_hash: hash(&c["quorum_hash"]),
            signature: bytes(&c["signature"]),
        },
        normalized_label: j["normalized_label"].as_str().unwrap().to_string(),
        dpns_proof: bytes(&j["dpns_proof"]),
        identity_proof: bytes(&j["identity_proof"]),
    };
    let t = std::time::Instant::now();
    match dash_lane_core::verify(&input) {
        Ok(s) => {
            println!("VERIFIED in {:?}", t.elapsed());
            println!(
                "  core   {} {} -> {} {}",
                s.coreStartHeight,
                hex::encode(s.coreStartHash),
                s.coreEndHeight,
                hex::encode(s.coreEndHash)
            );
            println!(
                "  platform height {} time_ms {} protocol {}",
                s.platformHeight, s.platformTimeMs, s.protocolVersion
            );
            println!("  app_hash {}", hex::encode(s.appHash));
            println!(
                "  name {} ({}) -> identity {}",
                s.label,
                s.normalizedLabel,
                hex::encode(s.identityId)
            );
            println!("  balance {} credits, revision {}", s.balance, s.revision);
            for k in &s.keys {
                println!(
                    "  key {} purpose {} security {} eth {}",
                    k.id, k.purpose, k.securityLevel, k.ethAddress
                );
            }
            let pv = dash_lane_core::public_values(&s);
            std::fs::write(format!("{path}.public.bin"), &pv).unwrap();
            std::fs::write(
                format!("{path}.stdin.bin"),
                bincode::serialize(&input).unwrap(),
            )
            .unwrap();
            println!("  public values {} bytes", pv.len());
        }
        Err(e) => {
            eprintln!("REJECTED: {e:?}");
            std::process::exit(1);
        }
    }
}
