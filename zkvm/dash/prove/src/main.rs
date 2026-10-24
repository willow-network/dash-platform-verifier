//! dash-prove — SP1 host for the Dash username program.
//!
//! ```text
//! dash-prove vkey <elf>
//! dash-prove execute <elf> <stdin.bin> <expected-public.bin>
//! dash-prove prove <elf> <stdin.bin> <expected-public.bin> <out.json> [groth16|plonk]
//! ```
//! `stdin.bin` is the bincode `Input` and `expected-public.bin` the public values that
//! `dash-execrun` wrote from the native run; the zkVM's public values must equal them.

use std::time::Instant;

use anyhow::{bail, Context, Result};
use sp1_sdk::blocking::{ProveRequest, Prover, ProverClient};
#[allow(unused_imports)]
use sp1_sdk::ProvingKey;
use sp1_sdk::{Elf, HashableKey, SP1Stdin};

#[cfg(feature = "cuda")]
fn client() -> sp1_sdk::blocking::CudaProver {
    ProverClient::builder().cuda().build()
}
#[cfg(not(feature = "cuda"))]
fn client() -> sp1_sdk::blocking::CpuProver {
    ProverClient::builder().cpu().build()
}

fn stdin(path: &str) -> Result<SP1Stdin> {
    let mut st = SP1Stdin::new();
    st.write_slice(&std::fs::read(path).with_context(|| path.to_string())?);
    Ok(st)
}

fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let client = client();
    match a.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["vkey", elf] => {
            let pk = client.setup(Elf::from(std::fs::read(elf)?))?;
            println!("{}", pk.verifying_key().bytes32());
        }
        ["execute", elf, input, expected] => {
            let t = Instant::now();
            let (pv, report) = client
                .execute(Elf::from(std::fs::read(elf)?), stdin(input)?)
                .run()?;
            println!(
                "cycles {} in {:.2?}",
                report.total_instruction_count(),
                t.elapsed()
            );
            if pv.as_slice() != std::fs::read(expected)?.as_slice() {
                bail!("zkVM public values differ from the native run");
            }
            println!(
                "public values match the native run ({} bytes)",
                pv.as_slice().len()
            );
        }
        [cmd @ "prove", elf, input, expected, out, rest @ ..] => {
            let _ = cmd;
            let pk = client.setup(Elf::from(std::fs::read(elf)?))?;
            let vk = pk.verifying_key().clone();
            let t = Instant::now();
            let req = client.prove(&pk, stdin(input)?);
            let proof = match rest.first().copied().unwrap_or("groth16") {
                "groth16" => req.groth16().run()?,
                "plonk" => req.plonk().run()?,
                m => bail!("unknown mode {m}"),
            };
            let secs = t.elapsed().as_secs_f64();
            client.verify(&proof, &vk, None).context("verify")?;
            if proof.public_values.as_slice() != std::fs::read(expected)?.as_slice() {
                bail!("proof public values differ from the native run");
            }
            let j = serde_json::json!({
                "vkey": vk.bytes32(),
                "public_values": format!("0x{}", hex::encode(proof.public_values.as_slice())),
                "proof": format!("0x{}", hex::encode(proof.bytes())),
                "prove_secs": secs,
            });
            std::fs::write(out, serde_json::to_vec_pretty(&j)?)?;
            println!("proved in {secs:.1}s, verified, wrote {out}");
        }
        _ => bail!("usage: dash-prove vkey|execute|prove ..."),
    }
    Ok(())
}
