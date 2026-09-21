//! Deterministic validation and identity generation for analysis profiles.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::{CString, c_char};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

const DOMAIN: &[u8] = b"unifi-qemu-analysis\0";

#[derive(Debug, Error)]
pub enum ProfileError {
    #[error("analysis must be a mapping")]
    AnalysisType,
    #[error("analysis.enabled must be true")]
    Disabled,
    #[error("analysis.identity_seed must be a non-empty string")]
    Seed,
    #[error("analysis.profile must be malware-analysis")]
    Profile,
    #[error("invalid clone id")]
    CloneId,
    #[error("invalid analysis field: {0}")]
    Field(String),
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("ACPI table I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Debug, Deserialize)]
pub struct AnalysisInput {
    pub analysis: Value,
    #[serde(default)]
    pub network: Value,
    #[serde(default)]
    pub os: Value,
    #[serde(default)]
    pub cpu: Value,
    #[serde(default)]
    pub vcpu: Value,
    #[serde(default)]
    pub memory: Value,
    #[serde(default)]
    pub channels: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Identity {
    pub uuid: String,
    pub mac: String,
    pub serials: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ValidatedProfile {
    pub schema_version: u32,
    pub profile: String,
    pub identity_seed_sha256: String,
    pub identity: Identity,
    pub network_mode: String,
    pub os: Value,
    pub cpu: Value,
    pub vcpu: Value,
    pub memory: Value,
    pub smbios: Value,
    pub acpi: Value,
    pub device_descriptors: Value,
    pub sensors: Value,
    pub pci: Value,
}

fn hash(seed: &str, label: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(seed.as_bytes());
    hasher.update([0]);
    hasher.update(label.as_bytes());
    hasher.finalize().into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn identity(seed: &str) -> Identity {
    let mut uuid_bytes: [u8; 16] = hash(seed, "uuid")[..16]
        .try_into()
        .expect("fixed digest size");
    uuid_bytes[6] = (uuid_bytes[6] & 0x0f) | 0x40;
    uuid_bytes[8] = (uuid_bytes[8] & 0x3f) | 0x80;
    let uuid = format!(
        "{}-{}-{}-{}-{}",
        hex(&uuid_bytes[0..4]),
        hex(&uuid_bytes[4..6]),
        hex(&uuid_bytes[6..8]),
        hex(&uuid_bytes[8..10]),
        hex(&uuid_bytes[10..16])
    );
    let mac_tail = hash(seed, "mac")[..5]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    let mac = format!("02:{mac_tail}");
    let seed_hash = hex(&Sha256::digest(seed.as_bytes()));
    let serials = ["bios", "system", "board", "chassis", "processor", "memory"]
        .into_iter()
        .map(|kind| {
            (
                kind.to_owned(),
                format!("AN-{}-{}", kind.to_uppercase(), &seed_hash[..12]),
            )
        })
        .collect();
    Identity { uuid, mac, serials }
}

fn required_string(value: Option<&Value>, field: &str) -> Result<String, ProfileError> {
    let value = value
        .and_then(Value::as_str)
        .ok_or_else(|| ProfileError::Field(field.into()))?;
    if value.is_empty() || value.contains('\0') {
        return Err(ProfileError::Field(field.into()));
    }
    Ok(value.to_owned())
}

fn mapping(value: Option<&Value>, field: &str) -> Result<Value, ProfileError> {
    match value {
        None => Ok(Value::Object(Default::default())),
        Some(Value::Object(_)) => Ok(value.cloned().expect("value exists")),
        Some(_) => Err(ProfileError::Field(format!("{field} must be a mapping"))),
    }
}

pub fn clone_identity(seed: &str, clone_id: &str) -> Result<Identity, ProfileError> {
    if clone_id.is_empty()
        || clone_id.len() > 64
        || !clone_id.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
        })
        || !clone_id
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_alphanumeric())
    {
        return Err(ProfileError::CloneId);
    }
    Ok(identity(&format!("{seed}\0clone\0{clone_id}")))
}

pub fn validate(input: &AnalysisInput) -> Result<ValidatedProfile, ProfileError> {
    let analysis = input
        .analysis
        .as_object()
        .ok_or(ProfileError::AnalysisType)?;
    if analysis.get("enabled") != Some(&Value::Bool(true)) {
        return Err(ProfileError::Disabled);
    }
    if analysis.get("profile").and_then(Value::as_str) != Some("malware-analysis") {
        return Err(ProfileError::Profile);
    }
    let seed = required_string(analysis.get("identity_seed"), "analysis.identity_seed")?;
    let identity = match analysis.get("clone").and_then(Value::as_str) {
        Some(clone) => clone_identity(&seed, clone)?,
        None => identity(&seed),
    };
    let network_mode = input
        .network
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("user");
    if !matches!(network_mode, "disabled" | "user" | "bridge") {
        return Err(ProfileError::Field("network.type".into()));
    }
    Ok(ValidatedProfile {
        schema_version: 1,
        profile: "malware-analysis".into(),
        identity_seed_sha256: hex(&Sha256::digest(seed.as_bytes())),
        identity,
        network_mode: network_mode.into(),
        os: input.os.clone(),
        cpu: input.cpu.clone(),
        vcpu: input.vcpu.clone(),
        memory: input.memory.clone(),
        smbios: mapping(analysis.get("smbios"), "analysis.smbios")?,
        acpi: mapping(analysis.get("acpi"), "analysis.acpi")?,
        device_descriptors: mapping(
            analysis.get("device_descriptors"),
            "analysis.device_descriptors",
        )?,
        sensors: mapping(analysis.get("sensors"), "analysis.sensors")?,
        pci: mapping(analysis.get("pci"), "analysis.pci")?,
    })
}

fn validate_resolved(input: &AnalysisInput) -> Result<ValidatedProfile, ProfileError> {
    let analysis = input
        .analysis
        .as_object()
        .ok_or(ProfileError::AnalysisType)?;
    if analysis.get("profile").and_then(Value::as_str) != Some("malware-analysis") {
        return Err(ProfileError::Profile);
    }
    let seed_hash = required_string(
        analysis.get("identity_seed_sha256"),
        "analysis.identity_seed_sha256",
    )?;
    if seed_hash.len() != 64
        || !seed_hash
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return Err(ProfileError::Field("analysis.identity_seed_sha256".into()));
    }
    let identity: Identity = serde_json::from_value(
        analysis
            .get("identity")
            .cloned()
            .ok_or_else(|| ProfileError::Field("analysis.identity".into()))?,
    )?;
    if identity.uuid.is_empty() || identity.mac.is_empty() || identity.serials.is_empty() {
        return Err(ProfileError::Field("analysis.identity".into()));
    }
    let network_mode = input
        .network
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("user");
    if !matches!(network_mode, "disabled" | "user" | "bridge") {
        return Err(ProfileError::Field("network.type".into()));
    }
    Ok(ValidatedProfile {
        schema_version: 1,
        profile: "malware-analysis".into(),
        identity_seed_sha256: seed_hash,
        identity,
        network_mode: network_mode.into(),
        os: input.os.clone(),
        cpu: input.cpu.clone(),
        vcpu: input.vcpu.clone(),
        memory: input.memory.clone(),
        smbios: mapping(analysis.get("smbios"), "analysis.smbios")?,
        acpi: mapping(analysis.get("acpi"), "analysis.acpi")?,
        device_descriptors: mapping(
            analysis.get("device_descriptors"),
            "analysis.device_descriptors",
        )?,
        sensors: mapping(analysis.get("sensors"), "analysis.sensors")?,
        pci: mapping(analysis.get("pci"), "analysis.pci")?,
    })
}

pub fn validate_json(input: &str) -> Result<String, ProfileError> {
    let parsed: AnalysisInput = serde_json::from_str(input)?;
    let resolved = parsed
        .analysis
        .as_object()
        .is_some_and(|analysis| analysis.get("identity_seed").is_none());
    let validated = if resolved {
        validate_resolved(&parsed)?
    } else {
        validate(&parsed)?
    };
    Ok(serde_json::to_string_pretty(&validated)?)
}

/// Validate a JSON profile through the narrow QEMU C ABI.
///
/// The returned string is owned by this library and must be released with
/// [`analysis_profile_free_string`]. A null pointer means validation failed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn analysis_profile_validate_json(
    input: *const u8,
    length: usize,
) -> *mut c_char {
    if input.is_null() {
        return std::ptr::null_mut();
    }
    let bytes = unsafe { std::slice::from_raw_parts(input, length) };
    let text = match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => return std::ptr::null_mut(),
    };
    match validate_json(text)
        .ok()
        .and_then(|value| CString::new(value).ok())
    {
        Some(value) => value.into_raw(),
        None => std::ptr::null_mut(),
    }
}

/// Release a string returned by [`analysis_profile_validate_json`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn analysis_profile_free_string(value: *mut c_char) {
    if !value.is_null() {
        drop(unsafe { CString::from_raw(value) });
    }
}

pub fn clone_identity_json(seed: &str, clone_id: &str) -> Result<String, ProfileError> {
    Ok(serde_json::to_string_pretty(&clone_identity(
        seed, clone_id,
    )?)?)
}

fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let first = chunk[0] as u32;
        let second = chunk.get(1).copied().unwrap_or(0) as u32;
        let third = chunk.get(2).copied().unwrap_or(0) as u32;
        let value = (first << 16) | (second << 8) | third;
        output.push(ALPHABET[((value >> 18) & 0x3f) as usize] as char);
        output.push(ALPHABET[((value >> 12) & 0x3f) as usize] as char);
        output.push(if chunk.len() > 1 {
            ALPHABET[((value >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            ALPHABET[(value & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    output
}

fn acpi_name(name: &str, index: usize) -> String {
    let clean: String = name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
                character
            } else {
                '_'
            }
        })
        .collect();
    let clean = clean.trim_matches(['.', '_']).to_owned();
    format!(
        "{index:03}-{}.bin",
        if clean.is_empty() { "ACPI" } else { &clean }
    )
}

/// Capture Linux ACPI sysfs tables for scripted host evidence collection.
pub fn acpi_dump_json(
    root: &Path,
    include_data: bool,
    output_dir: Option<&Path>,
) -> Result<String, ProfileError> {
    let mut tables = Vec::new();
    let bases = [
        root.join("sys/firmware/acpi/tables"),
        root.join("sys/firmware/acpi/tables/dynamic"),
    ];
    for base in bases {
        let entries = match fs::read_dir(&base) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        let mut paths: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.is_file())
            .collect();
        paths.sort();
        for path in paths {
            let data = match fs::read(&path) {
                Ok(data) => data,
                Err(_) => continue,
            };
            let name = path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("ACPI")
                .to_owned();
            let signature = String::from_utf8_lossy(&data[..data.len().min(4)]).to_string();
            let mut item = serde_json::Map::new();
            item.insert("name".into(), Value::String(name));
            item.insert("source".into(), Value::String(path.display().to_string()));
            item.insert("signature".into(), Value::String(signature));
            item.insert("length".into(), Value::from(data.len()));
            item.insert("sha256".into(), Value::String(hex(&Sha256::digest(&data))));
            if data.len() >= 10 {
                item.insert("revision".into(), Value::from(data[8]));
                item.insert("checksum".into(), Value::from(data[9]));
                item.insert(
                    "checksum_valid".into(),
                    Value::from(data.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) == 0),
                );
            }
            if include_data && output_dir.is_none() {
                item.insert("data_base64".into(), Value::String(base64(&data)));
            }
            if let Some(directory) = output_dir {
                fs::create_dir_all(directory)?;
                let target = directory.join(acpi_name(
                    item.get("name").and_then(Value::as_str).unwrap_or("ACPI"),
                    tables.len(),
                ));
                fs::write(&target, data)?;
                item.insert("path".into(), Value::String(target.display().to_string()));
            }
            tables.push(Value::Object(item));
        }
    }
    Ok(serde_json::to_string_pretty(&serde_json::json!({
        "schema_version": 1, "kind": "acpi-table-dump", "os": "Linux",
        "method": "sysfs", "table_count": tables.len(), "tables": tables,
    }))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn identity_is_stable_and_versioned() {
        let left = identity("seed");
        assert_eq!(left, identity("seed"));
        assert_eq!(&left.mac[..3], "02:");
        assert_ne!(left.uuid, identity("other").uuid);
    }

    #[test]
    fn validates_and_rejects_unsafe_profiles() {
        let input: AnalysisInput = serde_json::from_value(serde_json::json!({
            "analysis": {"enabled": true, "profile": "malware-analysis", "identity_seed": "seed"}
        }))
        .unwrap();
        assert!(validate(&input).is_ok());
        let bad = serde_json::from_value::<AnalysisInput>(serde_json::json!({
            "analysis": {"enabled": true, "profile": "malware-analysis", "identity_seed": ""}
        }))
        .unwrap();
        assert!(matches!(validate(&bad), Err(ProfileError::Field(_))));
    }

    #[test]
    fn validates_resolved_non_secret_profile_payload() {
        let resolved = identity("seed");
        let seed_hash = hex(&Sha256::digest(b"seed"));
        let payload = serde_json::json!({
            "analysis": {
                "schema_version": 1,
                "profile": "malware-analysis",
                "identity_seed_sha256": seed_hash,
                "identity": resolved,
                "smbios": {}, "acpi": {}, "device_descriptors": {}, "sensors": {}, "pci": {}
            },
            "network": {"type": "disabled"}, "cpu": "host,kvm=off", "vcpu": 2, "memory": "8GiB"
        });
        assert!(validate_json(&serde_json::to_string(&payload).unwrap()).is_ok());
    }

    #[test]
    fn acpi_dump_reports_fixture_metadata_and_raw_table() {
        let root = std::env::temp_dir().join(format!(
            "machineemu-acpi-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let table_dir = root.join("sys/firmware/acpi/tables");
        std::fs::create_dir_all(&table_dir).unwrap();
        let mut table = b"FACP\x10\x00\x00\x00\x01\x00payload".to_vec();
        table[9] = (0u8).wrapping_sub(table.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)));
        std::fs::write(table_dir.join("FACP"), &table).unwrap();
        let output = root.join("raw");
        let report: Value =
            serde_json::from_str(&acpi_dump_json(&root, false, Some(&output)).unwrap()).unwrap();
        assert_eq!(report["table_count"], 1);
        assert_eq!(report["tables"][0]["signature"], "FACP");
        assert_eq!(report["tables"][0]["checksum_valid"], true);
        assert_eq!(std::fs::read(output.join("000-FACP.bin")).unwrap(), table);
        std::fs::remove_dir_all(root).unwrap();
    }
}
