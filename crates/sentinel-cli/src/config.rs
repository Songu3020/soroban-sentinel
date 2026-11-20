//! Loading and preflight validation for one-shot contract manifests.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use sentinel_core::adapters::{
    derive_persistent_symbol_key, derive_persistent_xdr_key, parse_contract_id,
};
use sentinel_core::domain::DEFAULT_WARNING_LEDGERS;
use sentinel_core::usecases::ScanRequest;
use serde::Deserialize;

use crate::commands::scan::{resolve_rpc_url, resolve_threshold_config};

const MAX_FILE_BYTES: usize = 256 * 1024;
const MAX_CONTRACTS: usize = 100;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    #[serde(default)]
    defaults: Defaults,
    contracts: Vec<toml::Value>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Defaults {
    network: Option<String>,
    rpc_url: Option<String>,
    #[serde(alias = "threshold")]
    warning_threshold: Option<u32>,
    critical_threshold: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Contract {
    id: String,
    name: Option<String>,
    #[serde(default)]
    keys: Vec<String>,
    #[serde(default)]
    key_xdr: Vec<String>,
    #[serde(alias = "threshold")]
    warning_threshold: Option<u32>,
    critical_threshold: Option<u32>,
}

pub struct ManifestScan {
    pub rpc_url: String,
    pub contracts: Vec<ContractScan>,
}

pub struct ContractScan {
    pub name: Option<String>,
    pub request: ScanRequest,
}

/// Read a bounded manifest and validate the entire fleet before returning scan requests.
pub fn load_manifest(path: &Path, rpc_env: Option<&str>) -> Result<ManifestScan, String> {
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| {
            file.take((MAX_FILE_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
        })
        .map_err(|error| format!("{}: {error}", path.display()))?;
    parse_manifest(&bytes, rpc_env).map_err(|error| format!("{}: {error}", path.display()))
}

fn parse_manifest(bytes: &[u8], rpc_env: Option<&str>) -> Result<ManifestScan, String> {
    if bytes.len() > MAX_FILE_BYTES {
        return Err(format!("manifest exceeds {MAX_FILE_BYTES} bytes"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "manifest must be UTF-8".to_owned())?;
    let raw: Manifest = toml::from_str(text).map_err(|error| error.to_string())?;
    if !(1..=MAX_CONTRACTS).contains(&raw.contracts.len()) {
        return Err(format!(
            "manifest must contain 1 to {MAX_CONTRACTS} contracts"
        ));
    }

    let defaults = raw.defaults;
    let network = defaults.network.as_deref().unwrap_or("testnet");
    if let Some(url) = &defaults.rpc_url {
        resolve_rpc_url(network, Some(url))
            .map_err(|_| "defaults.rpc_url must be a valid HTTP(S) URL".to_owned())?;
    }
    let endpoint = rpc_env.or(defaults.rpc_url.as_deref());
    let rpc_url = resolve_rpc_url(network, endpoint).map_err(|error| {
        if rpc_env.is_some() {
            "SOROBAN_RPC_URL must be a valid HTTP(S) URL".to_owned()
        } else {
            format!("defaults: {error}")
        }
    })?;
    let warning = defaults
        .warning_threshold
        .unwrap_or(DEFAULT_WARNING_LEDGERS);
    resolve_threshold_config(warning, defaults.critical_threshold)
        .map_err(|error| format!("defaults: {error}"))?;

    let contracts = raw
        .contracts
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            let label = value.get("id").and_then(toml::Value::as_str).map_or_else(
                || format!("contracts[{}]", index + 1),
                |id| format!("contract {id}"),
            );
            let result = (|| -> Result<ContractScan, String> {
                let contract: Contract = value
                    .try_into()
                    .map_err(|e: toml::de::Error| e.to_string())?;
                let id = parse_contract_id(&contract.id).map_err(|e| e.to_string())?;
                let thresholds = resolve_threshold_config(
                    contract.warning_threshold.unwrap_or(warning),
                    contract.critical_threshold.or(defaults.critical_threshold),
                )?;
                for key in &contract.keys {
                    derive_persistent_symbol_key(&id, key)
                        .map_err(|error| format!("keys entry {key:?}: {error}"))?;
                }
                for (index, key) in contract.key_xdr.iter().enumerate() {
                    derive_persistent_xdr_key(&id, key)
                        .map_err(|error| format!("key_xdr[{}]: {error}", index + 1))?;
                }
                Ok(ContractScan {
                    name: contract.name,
                    request: ScanRequest::new(contract.id)
                        .with_network(network)
                        .with_threshold_config(thresholds)
                        .with_persistent_symbols(contract.keys)
                        .with_persistent_xdr_keys(contract.key_xdr),
                })
            })();
            result.map_err(|error| format!("{label}: {error}"))
        })
        .collect::<Result<_, _>>()?;

    Ok(ManifestScan { rpc_url, contracts })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";

    #[test]
    fn example_config_parses_and_resolves_overrides() {
        let config = parse_manifest(
            include_bytes!("../../../sentinel.example.toml"),
            Some("https://rpc.example.com"),
        )
        .unwrap();
        assert_eq!(config.rpc_url, "https://rpc.example.com");
        assert_eq!(config.contracts.len(), 2);
        assert_eq!(config.contracts[0].name.as_deref(), Some("Token"));
        assert_eq!(config.contracts[0].request.persistent_symbols, ["COUNTER"]);
        let pool = &config.contracts[1].request;
        assert_eq!(pool.network.as_deref(), Some("testnet"));
        assert_eq!(pool.threshold_config.warning_ledgers, 86400);
        assert_eq!(pool.threshold_config.critical_ledgers, 17280);
    }

    #[test]
    fn invalid_contract_fields_and_keys_include_contract_id() {
        for (line, expected) in [
            ("unexpected = 1", "unknown field"),
            ("warning_threshold = 0", "Warning threshold"),
            ("critical_threshold = 999999", "Critical threshold"),
            ("key_xdr = ['invalid!']", "key_xdr[1]"),
        ] {
            let input = format!("[[contracts]]\nid = '{ID}'\n{line}");
            let error = parse_manifest(input.as_bytes(), None).err().unwrap();
            assert!(error.contains(ID), "{error}");
            assert!(error.contains(expected), "{error}");
        }
        let error = parse_manifest(b"[[contracts]]\nid = 'bad-id'", None)
            .err()
            .unwrap();
        assert!(error.contains("bad-id"), "{error}");
    }

    #[test]
    fn manifest_bounds_and_default_fields_are_validated() {
        let oversized = vec![b' '; MAX_FILE_BYTES + 1];
        let contract = format!("[[contracts]]\nid = '{ID}'\n");
        let too_many = contract.repeat(MAX_CONTRACTS + 1);
        for (input, expected) in [
            (oversized.as_slice(), "exceeds"),
            (too_many.as_bytes(), "1 to 100"),
            (b"contracts = []".as_slice(), "1 to 100"),
            (
                b"contracts = []\nunknown = true".as_slice(),
                "unknown field",
            ),
        ] {
            let error = parse_manifest(input, None).err().unwrap();
            assert!(error.contains(expected), "{error}");
        }
        let unknown_default = format!("[defaults]\nunknown = true\n{contract}");
        let error = parse_manifest(unknown_default.as_bytes(), None)
            .err()
            .unwrap();
        assert!(error.contains("unknown field"), "{error}");
    }
}
