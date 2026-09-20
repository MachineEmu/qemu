//! Deterministic validation and identity generation for analysis profiles.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
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

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
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

pub fn validate_json(input: &str) -> Result<String, ProfileError> {
    let parsed: AnalysisInput = serde_json::from_str(input)?;
    Ok(serde_json::to_string_pretty(&validate(&parsed)?)?)
}

pub fn clone_identity_json(seed: &str, clone_id: &str) -> Result<String, ProfileError> {
    Ok(serde_json::to_string_pretty(&clone_identity(
        seed, clone_id,
    )?)?)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
