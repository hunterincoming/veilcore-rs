//! Several contracts (spec 9.4): which of VeilCore's pinned contracts a check reads.
//!
//! A verifier holds its own pinned list of contracts, per network. A contract is identified
//! only by its address on that list: never by a version or `predecessor` field in the
//! contract's own state, a record or a registry answer. A transaction is read by the one pinned
//! contract it calls. The same commitment on two contracts is two records with two dates, never
//! joined. Off mainnet, a check names its contract version; a defaulted version fails.
//!
//! Like the SDK's `pinned-contracts.ts`, this module holds no list of its own and reads no
//! ledger: the caller passes the list it pins (VeilCore's is in `deployments/mainnet.json` and
//! `deployments/preprod.json` in the VeilCore application repository), so a checker can't pick
//! up a contract from anywhere else. Addresses are 64 lowercase hex characters; any other form
//! is refused, never normalised, so that letter case can't hide a second pinned contract.

use serde_json::Value;

/// One contract on a verifier's pinned list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedContract {
    pub network: String,
    /// 64 lowercase hex characters.
    pub address: String,
    pub kind: ContractKind,
    /// The contract version, as the list gives it.
    pub version: u64,
    /// What every date from this contract is shown with.
    pub name: String,
}

/// The main contract or the claims contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractKind {
    Main,
    Claims,
}

/// Why a check was refused, as the spec's vectors name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractRefusal {
    MalformedAddress,
    NotPinned,
    VersionNotNamed,
    VersionMismatch,
    NoPinnedContract,
    SeveralPinnedContracts,
    NamedContractNotCalled,
}

impl ContractRefusal {
    /// The name the conformance vectors use.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MalformedAddress => "malformed-address",
            Self::NotPinned => "not-pinned",
            Self::VersionNotNamed => "version-not-named",
            Self::VersionMismatch => "version-mismatch",
            Self::NoPinnedContract => "no-pinned-contract",
            Self::SeveralPinnedContracts => "several-pinned-contracts",
            Self::NamedContractNotCalled => "named-contract-not-called",
        }
    }
}

/// The contracts a check reads, or why it is refused.
pub type ContractChoice<'a> = Result<Vec<&'a PinnedContract>, ContractRefusal>;

/// A whole number from 1 to 2^53 - 1, as JSON may write it (2 or 2.0), like JavaScript's
/// `Number.isSafeInteger(v) && v >= 1`.
fn whole(v: &Value) -> Option<u64> {
    const MAX: u64 = (1u64 << 53) - 1;
    v.as_u64()
        .or_else(|| v.as_f64().filter(|f| f.fract() == 0.0 && *f >= 1.0 && *f <= MAX as f64).map(|f| f as u64))
        .filter(|v| *v >= 1 && *v <= MAX)
}

fn hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A pinned list from JSON (an array of `{ network, address, kind: "main" | "claims", version,
/// name }`). Refuses, naming the problem, any list it can't read whole: a checker must never run
/// on a list it half understood.
pub fn pinned_list(v: &Value) -> Result<Vec<PinnedContract>, String> {
    let entries = v.as_array().ok_or("pinned list must be an array")?;
    let mut out: Vec<PinnedContract> = Vec::with_capacity(entries.len());
    for e in entries {
        let o = e.as_object().ok_or("pinned list: an entry is not an object")?;
        let network = o
            .get("network")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or("pinned list: an entry has no network")?;
        let address = o
            .get("address")
            .and_then(Value::as_str)
            .filter(|s| hex64(s))
            .ok_or("pinned list: an address is not 64 lowercase hex")?;
        let kind = match o.get("kind").and_then(Value::as_str) {
            Some("main") => ContractKind::Main,
            Some("claims") => ContractKind::Claims,
            _ => return Err(format!("pinned list: {address} has no kind main or claims")),
        };
        let version = o
            .get("version")
            .and_then(whole)
            .ok_or_else(|| format!("pinned list: {address} has no version"))?;
        let name = o
            .get("name")
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| format!("pinned list: {address} has no name"))?;
        if out.iter().any(|c| c.network == network && c.address == address) {
            return Err(format!("pinned list: {address} is listed twice on {network}"));
        }
        out.push(PinnedContract {
            network: network.to_string(),
            address: address.to_string(),
            kind,
            version,
            name: name.to_string(),
        });
    }
    Ok(out)
}

/// A version is named when the check states it. Off mainnet one must be; on mainnet it may be.
fn named_version(network: &str, version: Option<&Value>) -> Result<Option<u64>, ContractRefusal> {
    match version {
        None | Some(Value::Null) if network == "mainnet" => Ok(None),
        None | Some(Value::Null) => Err(ContractRefusal::VersionNotNamed),
        Some(v) => whole(v).map(Some).ok_or(ContractRefusal::VersionNotNamed),
    }
}

/// The pinned contracts a check reads (spec 9.4 (1), (2) and (5)).
///
/// With an address: that contract, only if it is on the list for this network. Without one:
/// every pinned contract on the network (of the named version, if one is named), never a default
/// one. What the contract's own state says about itself is never read.
pub fn pinned_contracts<'a>(
    list: &'a [PinnedContract],
    network: &str,
    address: Option<&Value>,
    version: Option<&Value>,
) -> ContractChoice<'a> {
    let named = named_version(network, version)?;
    if let Some(address) = address {
        let a = address
            .as_str()
            .filter(|s| hex64(s))
            .ok_or(ContractRefusal::MalformedAddress)?;
        let entry = list
            .iter()
            .find(|c| c.network == network && c.address == a)
            .ok_or(ContractRefusal::NotPinned)?;
        if named.is_some_and(|v| v != entry.version) {
            return Err(ContractRefusal::VersionMismatch);
        }
        return Ok(vec![entry]);
    }
    let all: Vec<&PinnedContract> = list
        .iter()
        .filter(|c| c.network == network && named.map_or(true, |v| c.version == v))
        .collect();
    if all.is_empty() {
        Err(ContractRefusal::NoPinnedContract)
    } else {
        Ok(all)
    }
}

/// The one pinned contract a transaction is decoded by (spec 9.4 (1) and (3)): the pinned
/// contract it calls. A transaction that calls none, or more than one, is refused. Calls to
/// contracts that are not pinned don't count either way, but every address in `calls` must be
/// 64 lowercase hex. `named` is the address the record names, if it names one: the transaction
/// must call that contract.
pub fn contract_for_transaction<'a>(
    list: &'a [PinnedContract],
    network: &str,
    calls: &[Value],
    version: Option<&Value>,
    named: Option<&Value>,
) -> ContractChoice<'a> {
    let v = named_version(network, version)?;
    let calls: Vec<&str> = calls
        .iter()
        .map(|c| c.as_str().filter(|s| hex64(s)))
        .collect::<Option<_>>()
        .ok_or(ContractRefusal::MalformedAddress)?;
    if let Some(n) = named {
        pinned_contracts(list, network, Some(n), version)?;
    }
    let called: Vec<&PinnedContract> = list
        .iter()
        .filter(|c| c.network == network && calls.contains(&c.address.as_str()))
        .collect();
    match called.len() {
        0 => return Err(ContractRefusal::NoPinnedContract),
        1 => {}
        _ => return Err(ContractRefusal::SeveralPinnedContracts),
    }
    if v.is_some_and(|v| v != called[0].version) {
        return Err(ContractRefusal::VersionMismatch);
    }
    if named.and_then(Value::as_str).is_some_and(|n| n != called[0].address) {
        return Err(ContractRefusal::NamedContractNotCalled);
    }
    Ok(called)
}

/// A commitment dated by a pinned contract (spec 9.4 (4)): every date with the contract that
/// gave it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatedRecord {
    pub commitment: String,
    pub date: String,
    /// The pinned entry's name.
    pub contract: String,
    pub address: String,
    pub version: u64,
}

/// A sighting that gives no date, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedSighting {
    pub address: String,
    pub commitment: String,
    pub refused: ContractRefusal,
}

/// Dates for commitments found on several contracts (spec 9.4 (4)). Each sighting
/// (`{ address, commitment, date }`) on a pinned contract is its own record with its own date
/// and the name of the contract that gave it. The same commitment on two contracts stays two
/// records: nothing is merged, and no record takes another's date. A sighting on a contract
/// that is not pinned gives no date.
pub fn dated_records(
    list: &[PinnedContract],
    network: &str,
    sightings: &[Value],
    version: Option<&Value>,
) -> (Vec<DatedRecord>, Vec<RefusedSighting>) {
    let mut records = Vec::new();
    let mut refused = Vec::new();
    for s in sightings {
        let text = |k: &str| s.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
        match pinned_contracts(list, network, s.get("address"), version) {
            Ok(c) => records.push(DatedRecord {
                commitment: text("commitment"),
                date: text("date"),
                contract: c[0].name.clone(),
                address: c[0].address.clone(),
                version: c[0].version,
            }),
            Err(r) => refused.push(RefusedSighting {
                address: text("address"),
                commitment: text("commitment"),
                refused: r,
            }),
        }
    }
    (records, refused)
}
