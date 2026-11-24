//! Several contracts (spec 9.4): every vector in veilcore-sdk's pinned-contracts-v1.json, with
//! the expected result compared as the SDK's runner compares it (conformance/run.mjs).

use serde_json::{json, Value};
use veilcore_records::pinned::{
    contract_for_transaction, dated_records, pinned_contracts, pinned_list, ContractChoice, PinnedContract,
};

fn vectors() -> Value {
    serde_json::from_str(include_str!("vectors/pinned-contracts-v1.json")).unwrap()
}

fn lists(v: &Value) -> std::collections::BTreeMap<String, Vec<PinnedContract>> {
    v["lists"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, l)| (k.clone(), pinned_list(l).unwrap()))
        .collect()
}

fn addresses(r: ContractChoice) -> Value {
    match r {
        Ok(c) => json!({ "ok": true, "contracts": c.iter().map(|c| c.address.clone()).collect::<Vec<_>>() }),
        Err(e) => json!({ "ok": false, "refused": e.as_str() }),
    }
}

#[test]
fn contract_choices() {
    let v = vectors();
    let l = lists(&v);
    let all = v["choices"].as_array().unwrap();
    assert!(!all.is_empty());
    for c in all {
        let q = &c["query"];
        let got = addresses(pinned_contracts(
            &l[c["list"].as_str().unwrap()],
            q["network"].as_str().unwrap(),
            q.get("address"),
            q.get("version"),
        ));
        assert_eq!(got, c["result"], "{}", c["name"]);
    }
}

#[test]
fn contract_transactions() {
    let v = vectors();
    let l = lists(&v);
    let all = v["transactions"].as_array().unwrap();
    assert!(!all.is_empty());
    for c in all {
        let q = &c["query"];
        let got = addresses(contract_for_transaction(
            &l[c["list"].as_str().unwrap()],
            q["network"].as_str().unwrap(),
            q["calls"].as_array().unwrap(),
            q.get("version"),
            q.get("named"),
        ));
        assert_eq!(got, c["result"], "{}", c["name"]);
    }
}

#[test]
fn contract_dates() {
    let v = vectors();
    let l = lists(&v);
    let all = v["dates"].as_array().unwrap();
    assert!(!all.is_empty());
    for c in all {
        let q = &c["query"];
        let (records, refused) = dated_records(
            &l[c["list"].as_str().unwrap()],
            q["network"].as_str().unwrap(),
            q["sightings"].as_array().unwrap(),
            q.get("version"),
        );
        let got = json!({
            "records": records.iter().map(|r| json!({
                "commitment": r.commitment, "date": r.date, "contract": r.contract, "address": r.address, "version": r.version,
            })).collect::<Vec<_>>(),
            "refused": refused.iter().map(|r| json!({
                "address": r.address, "commitment": r.commitment, "refused": r.refused.as_str(),
            })).collect::<Vec<_>>(),
        });
        assert_eq!(got, c["result"], "{}", c["name"]);
    }
}

#[test]
fn a_list_it_cannot_read_whole_is_refused() {
    let good = json!({ "network": "mainnet", "address": "11".repeat(32), "kind": "main", "version": 1, "name": "v1" });
    assert!(pinned_list(&json!([good.clone()])).is_ok());
    for bad in [
        json!({ "network": "mainnet", "address": "ab".repeat(32).to_uppercase(), "kind": "main", "version": 1, "name": "v1" }),
        json!({ "network": "mainnet", "address": format!("0x{}", "11".repeat(32)), "kind": "main", "version": 1, "name": "v1" }),
        json!({ "network": "mainnet", "address": "11".repeat(32), "kind": "router", "version": 1, "name": "v1" }),
        json!({ "network": "mainnet", "address": "11".repeat(32), "kind": "main", "version": 0, "name": "v1" }),
        json!({ "network": "mainnet", "address": "11".repeat(32), "kind": "main", "version": 1.5, "name": "v1" }),
        json!({ "network": "", "address": "11".repeat(32), "kind": "main", "version": 1, "name": "v1" }),
        json!({ "network": "mainnet", "address": "11".repeat(32), "kind": "main", "version": 1, "name": " " }),
    ] {
        assert!(pinned_list(&json!([bad])).is_err(), "{bad}");
    }
    assert!(pinned_list(&json!([good.clone(), good])).is_err(), "listed twice");
    assert!(pinned_list(&json!({})).is_err());
}

#[test]
fn a_sighting_that_names_no_contract_gives_no_date() {
    let v = vectors();
    let l = lists(&v);
    let c = "c0".repeat(32);
    let v2 = "b2".repeat(32);
    let unnamed = json!({ "commitment": c, "date": "2026-09-15T00:00:00Z" });
    let with_null = json!({ "address": null, "commitment": c, "date": "2026-09-15T00:00:00Z" });
    let on_v2 = json!({ "address": v2, "commitment": c, "date": "2026-12-02T00:00:00Z" });
    // Two contracts pinned: the first on the list must not lend its date.
    for s in [&unnamed, &with_null] {
        let (records, refused) = dated_records(&l["twoContracts"], "mainnet", &[s.clone(), on_v2.clone()], None);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].address, v2);
        assert_eq!(records[0].date, "2026-12-02T00:00:00Z");
        assert_eq!(refused.len(), 1);
        assert_eq!(refused[0].address, None);
        assert_eq!(refused[0].refused.as_str(), "no-contract-named");
    }
    // One contract pinned for the network and version: still no default.
    let (records, refused) = dated_records(&l["v1Only"], "preprod", &[unnamed.clone()], Some(&json!(1)));
    assert!(records.is_empty());
    assert_eq!(refused[0].refused.as_str(), "no-contract-named");
    // Off mainnet with no version named, the defaulted version is the reason given.
    let (_, refused) = dated_records(&l["twoContracts"], "preprod", &[unnamed.clone()], None);
    assert_eq!(refused[0].refused.as_str(), "version-not-named");
    // An empty address is malformed, not missing.
    let (_, refused) = dated_records(&l["twoContracts"], "mainnet", &[json!({ "address": "", "commitment": c, "date": "x" })], None);
    assert_eq!(refused[0].refused.as_str(), "malformed-address");
    // A check with no address still tries every pinned contract.
    assert_eq!(pinned_contracts(&l["twoContracts"], "mainnet", None, None).unwrap().len(), 3);
}
