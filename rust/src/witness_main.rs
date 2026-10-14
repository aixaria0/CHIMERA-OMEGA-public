#![forbid(unsafe_code)]

use chimera_omega::{encoding, witness::attest_kv_observer};
use serde::Serialize;
use serde_json::{json, Value};
use std::{fs::File, io::Read};

fn read(path: &str) -> Result<Vec<u8>, String> {
    let mut data = Vec::new();
    File::open(path)
        .map_err(|error| error.to_string())?
        .take(encoding::MAX_BYTES as u64 + 1)
        .read_to_end(&mut data)
        .map_err(|error| error.to_string())?;
    if data.len() > encoding::MAX_BYTES {
        return Err("input exceeds 1 MiB".into());
    }
    Ok(data)
}

fn write_json<T: Serialize>(path: &str, value: &T) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    if bytes.len() > encoding::MAX_BYTES {
        return Err(format!("output exceeds 1 MiB: {path}"));
    }
    std::fs::write(path, bytes).map_err(|error| error.to_string())
}

fn run(args: &[String]) -> Result<(Value, i32), String> {
    if args.len() != 7
        || args[1] != "attest-kv-observer"
        || args[3] != "--key"
        || args[5] != "--out"
    {
        return Err("usage: omega-witness attest-kv-observer <observer-receipt.json> --key <witness-secret.json> --out <attestation.json>".into());
    }
    if args[2] == args[4] || args[2] == args[6] || args[4] == args[6] {
        return Err(
            "observer receipt, witness secret and attestation paths must be distinct".into(),
        );
    }
    let attestation = attest_kv_observer(&read(&args[2])?, &read(&args[4])?)?;
    write_json(&args[6], &attestation)?;
    Ok((
        json!({
            "schema": "chimera-witness-authoring-result/v1",
            "status": "SIGNED_NOT_AUTHORIZED",
            "scope": "OFFLINE_ED25519_OBSERVER_ATTESTATION_ONLY",
            "witness_id": attestation.witness_id,
            "public_key": attestation.public_key,
            "observer_receipt_digest": attestation.observer_receipt_digest,
            "attestation_digest": attestation.digest,
            "attestation_path": args[6]
        }),
        0,
    ))
}

fn main() {
    let (output, code) = match run(&std::env::args().collect::<Vec<_>>()) {
        Ok(result) => result,
        Err(error) => (json!({"status":"REJECTED", "error":error}), 2),
    };
    match serde_json::to_string_pretty(&output) {
        Ok(text) => println!("{text}"),
        Err(_) => std::process::exit(2),
    }
    std::process::exit(code);
}
