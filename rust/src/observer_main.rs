#![forbid(unsafe_code)]

use chimera_omega::{encoding, observer::observe_kv};
use serde::Serialize;
use serde_json::{json, Value};
use std::{fs::File, io::Read};

fn read(path: &str) -> Result<Vec<u8>, String> {
    let mut data = Vec::new();
    File::open(path)
        .map_err(|e| e.to_string())?
        .take(encoding::MAX_BYTES as u64 + 1)
        .read_to_end(&mut data)
        .map_err(|e| e.to_string())?;
    if data.len() > encoding::MAX_BYTES {
        return Err("input exceeds 1 MiB".into());
    }
    Ok(data)
}

fn write_json<T: Serialize>(path: &str, value: &T) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    if bytes.len() > encoding::MAX_BYTES {
        return Err(format!("output exceeds 1 MiB: {path}"));
    }
    std::fs::write(path, bytes).map_err(|e| e.to_string())
}

fn run(args: &[String]) -> Result<(Value, i32), String> {
    if args.len() != 5 || args[1] != "observe-kv" || args[3] != "--out" {
        return Err(
            "usage: omega-observer observe-kv <execution-receipt.json> --out <observer-receipt.json>"
                .into(),
        );
    }
    if args[2] == args[4] {
        return Err("execution receipt and observer receipt paths must be distinct".into());
    }
    let receipt = observe_kv(&read(&args[2])?)?;
    write_json(&args[4], &receipt)?;
    Ok((
        json!({
            "schema": "chimera-kv-observer-authoring-result/v1",
            "status": "OBSERVED_NOT_AUTHORIZED",
            "scope": "LOCAL_KV_ARTIFACT_OBSERVER_ONLY",
            "execution_receipt_digest": receipt.execution_receipt_digest,
            "observer_source_digest": receipt.observer_source_digest,
            "observer_contract_digest": receipt.observer_contract_digest,
            "observation_digest": receipt.observation_digest,
            "observer_receipt_digest": receipt.digest,
            "observer_receipt_path": args[4]
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
