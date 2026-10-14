#![forbid(unsafe_code)]

use chimera_omega::{
    adapter::{run_kv, verify_kv_receipt},
    aether::import_aether_receipt,
    aether_historical::verify_aether_historical_journal,
    aether_journal::verify_aether_journal,
    aether_lattice::verify_aether_lineage,
    audit_archive::verify_audit_archive,
    compiler::import_compiler_evidence,
    encoding,
    model::Overall,
    observer::verify_kv_observer,
    seal, verify,
    witness::{seal_witness_policy, verify_kv_witness},
};
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
    if args.len() == 9
        && args[1] == "verify-aether-historical-journal"
        && args[3] == "--registry"
        && args[5] == "--context"
        && args[7] == "--expect-context"
    {
        let report = verify_aether_historical_journal(
            &read(&args[2])?,
            &read(&args[4])?,
            &read(&args[6])?,
            &args[8],
        )?;
        return Ok((serde_json::to_value(report).map_err(|e| e.to_string())?, 0));
    }
    if args.len() == 7
        && args[1] == "verify-audit-archive"
        && args[3] == "--context"
        && args[5] == "--expect-context"
    {
        let report = verify_audit_archive(&read(&args[2])?, &read(&args[4])?, &args[6])?;
        return Ok((serde_json::to_value(report).map_err(|e| e.to_string())?, 0));
    }
    if args.len() == 7
        && args[1] == "verify-aether-journal"
        && args[3] == "--context"
        && args[5] == "--expect-context"
    {
        let report = verify_aether_journal(&read(&args[2])?, &read(&args[4])?, &args[6])?;
        return Ok((serde_json::to_value(report).map_err(|e| e.to_string())?, 0));
    }
    if args.len() == 7
        && args[1] == "verify-aether-lineage"
        && args[3] == "--context"
        && args[5] == "--expect-context"
    {
        let report = verify_aether_lineage(&read(&args[2])?, &read(&args[4])?, &args[6])?;
        return Ok((serde_json::to_value(report).map_err(|e| e.to_string())?, 0));
    }
    if args.len() == 3 && args[1] == "seal-witness-policy" {
        let policy = seal_witness_policy(&read(&args[2])?)?;
        return Ok((serde_json::to_value(policy).map_err(|e| e.to_string())?, 0));
    }
    let is_kv_witness = args.len() == 17
        && args[1] == "verify-kv-witness"
        && args[3] == "--expect"
        && args[5] == "--receipt"
        && args[7] == "--observer"
        && args[9] == "--expect-observer"
        && args[11] == "--attestation"
        && args[13] == "--policy"
        && args[15] == "--expect-policy";
    if is_kv_witness {
        let report = verify_kv_witness(
            &read(&args[2])?,
            &args[4],
            &read(&args[6])?,
            &read(&args[8])?,
            &args[10],
            &read(&args[12])?,
            &read(&args[14])?,
            &args[16],
        )?;
        return Ok((serde_json::to_value(report).map_err(|e| e.to_string())?, 0));
    }
    if args.len() == 7
        && args[1] == "import-aether"
        && args[3] == "--expect"
        && args[5] == "--expect-source"
    {
        let result = import_aether_receipt(&read(&args[2])?, &args[4], &args[6])?;
        return Ok((serde_json::to_value(result).map_err(|e| e.to_string())?, 0));
    }
    if args.len() == 9
        && args[1] == "import-compiler"
        && args[5] == "--expect-report"
        && args[7] == "--fixture"
    {
        let result = import_compiler_evidence(
            &read(&args[2])?,
            &read(&args[3])?,
            &read(&args[4])?,
            &args[6],
            &args[8],
        )?;
        return Ok((serde_json::to_value(result).map_err(|e| e.to_string())?, 0));
    }
    if args.len() == 3 && args[1] == "seal" {
        let sealed = seal(&read(&args[2])?)?;
        return Ok((serde_json::to_value(sealed).map_err(|e| e.to_string())?, 0));
    }
    if args.len() == 7 && args[1] == "run-kv" && args[3] == "--package" && args[5] == "--receipt" {
        if args[2] == args[4] || args[2] == args[6] || args[4] == args[6] {
            return Err("scenario, package and receipt paths must be distinct".into());
        }
        let execution = run_kv(&read(&args[2])?)?;
        write_json(&args[4], &execution.package)?;
        write_json(&args[6], &execution.receipt)?;
        return Ok((
            json!({
                "schema": "chimera-kv-authoring-result/v1",
                "status": "AUTHORED_NOT_VERIFIED",
                "scope": "LOCAL_DETERMINISTIC_ADAPTER_EXECUTION_ONLY",
                "scenario_digest": execution.receipt.scenario_digest,
                "adapter_source_digest": execution.receipt.adapter_source_digest,
                "execution_contract_digest": execution.receipt.execution_contract_digest,
                "package_digest": execution.package.digest,
                "receipt_digest": execution.receipt.digest,
                "package_path": args[4],
                "receipt_path": args[6]
            }),
            0,
        ));
    }
    let is_kv_receipt = args.len() == 7
        && args[1] == "verify-kv-receipt"
        && args[3] == "--expect"
        && args[5] == "--receipt";
    if is_kv_receipt {
        let report = verify_kv_receipt(&read(&args[2])?, &args[4], &read(&args[6])?)?;
        return Ok((serde_json::to_value(report).map_err(|e| e.to_string())?, 0));
    }
    let is_kv_observer = args.len() == 11
        && args[1] == "verify-kv-observer"
        && args[3] == "--expect"
        && args[5] == "--receipt"
        && args[7] == "--observer"
        && args[9] == "--expect-observer";
    if is_kv_observer {
        let report = verify_kv_observer(
            &read(&args[2])?,
            &args[4],
            &read(&args[6])?,
            &read(&args[8])?,
            &args[10],
        )?;
        return Ok((serde_json::to_value(report).map_err(|e| e.to_string())?, 0));
    }
    let is_verify = args.len() == 5 && args[1] == "verify";
    let is_replay = args.len() == 7 && args[1] == "replay" && args[5] == "--receipt";
    if !(is_verify || is_replay) || args[3] != "--expect" {
        return Err("usage: omega verify-aether-historical-journal <export.json> --registry <registry.json> --context <context.json> --expect-context <reviewed-context-digest> | omega verify-audit-archive <archive.json> --context <context.json> --expect-context <reviewed-context-digest> | omega verify-aether-journal <export.json> --context <context.json> --expect-context <reviewed-context-digest> | omega verify-aether-lineage <evidence.json> --context <context.json> --expect-context <reviewed-context-digest> | omega seal-witness-policy <draft.json> | omega verify-kv-witness <package.json> --expect <package-digest> --receipt <execution-receipt.json> --observer <observer-receipt.json> --expect-observer <observer-digest> --attestation <attestation.json> --policy <policy.json> --expect-policy <policy-digest> | omega import-aether <receipt.json> --expect <digest> --expect-source <aether-revision> | omega import-compiler <package.ndjson> <context.json> <native-reports.json> --expect-report <sha256:...> --fixture <name> | omega seal <draft.json> | omega run-kv <scenario.json> --package <package.json> --receipt <receipt.json> | omega verify-kv-receipt <package.json> --expect <digest> --receipt <receipt.json> | omega verify-kv-observer <package.json> --expect <package-digest> --receipt <execution-receipt.json> --observer <observer-receipt.json> --expect-observer <observer-digest> | omega verify <package.json> --expect <digest> | omega replay <package.json> --expect <digest> --receipt <report.json>".into());
    }
    let report = verify(&read(&args[2])?, &args[4])?;
    let code = match report.status {
        Overall::LocallySupported => 0,
        Overall::Contradicted => 1,
        Overall::Inconclusive => 3,
    };
    let report = serde_json::to_value(report).map_err(|e| e.to_string())?;
    if is_verify {
        return Ok((report, code));
    }
    let prior = encoding::parse(&read(&args[6])?)?;
    let equal = encoding::canonical_json(&prior)? == encoding::canonical_json(&report)?;
    Ok((
        json!({
            "schema": "chimera-report-replay/v1",
            "status": if equal { "REPRODUCED" } else { "DIVERGENT" },
            "scope": "VERIFICATION_REPORT_ONLY_NOT_TARGET_EXECUTION",
            "report_digest": encoding::digest("report/v2", &report)?,
            "report": report
        }),
        if equal { code } else { 1 },
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
