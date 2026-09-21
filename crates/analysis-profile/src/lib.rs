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
///
/// # Safety
///
/// `input` must be null, or point to `length` readable bytes that stay valid
/// for the duration of the call.
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
///
/// # Safety
///
/// `value` must be null, or a pointer returned by
/// [`analysis_profile_validate_json`] that has not already been released.
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

/// Read a sysfs or procfs value, rejecting anything unusable as an identity
/// string. Sysfs happily returns empty files and NUL bytes on partially
/// populated firmware tables, and a profile carrying those would fail
/// validation later, far from the host that produced it.
fn host_string(path: &Path) -> Option<String> {
    let value = fs::read_to_string(path).ok()?;
    let value = value.trim().to_owned();
    if value.is_empty() || value.contains('\0') || value.chars().count() > 128 {
        return None;
    }
    Some(value)
}

fn insert_string(map: &mut serde_json::Map<String, Value>, key: &str, value: Option<String>) {
    if let Some(value) = value {
        map.insert(key.into(), Value::String(value));
    }
}

/// SMBIOS identity as Linux exposes it, minus the per-machine values.
///
/// The serial numbers, asset tags and system UUID under this directory are what
/// tie a machine to its owner; a clone that copied them would put a duplicate
/// of the host on the network and report the host's real identifiers if the
/// guest ever phones home. Those stay derived from the profile seed, so only
/// the fields that describe the hardware model are read here.
fn host_smbios(root: &Path) -> serde_json::Map<String, Value> {
    let dmi = root.join("sys/class/dmi/id");
    let mut smbios = serde_json::Map::new();
    for (key, file) in [
        ("bios_vendor", "bios_vendor"),
        ("bios_version", "bios_version"),
        ("bios_date", "bios_date"),
        ("system_manufacturer", "sys_vendor"),
        ("system_product", "product_name"),
        ("system_version", "product_version"),
        ("system_family", "product_family"),
        ("system_sku", "product_sku"),
        ("board_manufacturer", "board_vendor"),
        ("board_product", "board_name"),
        ("board_version", "board_version"),
        ("chassis_manufacturer", "chassis_vendor"),
        ("chassis_version", "chassis_version"),
    ] {
        insert_string(&mut smbios, key, host_string(&dmi.join(file)));
    }
    let cpuinfo = fs::read_to_string(root.join("proc/cpuinfo")).unwrap_or_default();
    let field = |name: &str| -> Option<String> {
        cpuinfo
            .lines()
            .find(|line| line.split(':').next().is_some_and(|key| key.trim() == name))
            .and_then(|line| line.split_once(':'))
            .map(|(_, value)| value.trim().to_owned())
            .filter(|value| !value.is_empty() && value.chars().count() <= 128)
    };
    insert_string(&mut smbios, "processor_manufacturer", field("vendor_id"));
    insert_string(&mut smbios, "processor_version", field("model name"));
    if let Some(speed) = field("cpu MHz").and_then(|value| value.parse::<f64>().ok()) {
        smbios.insert("processor_current_speed".into(), Value::from(speed as u64));
    }
    smbios
}

/// One SMBIOS structure: its type, the fixed-size formatted area, and the
/// strings that follow it.
struct DmiStructure {
    kind: u8,
    data: Vec<u8>,
    strings: Vec<String>,
}

impl DmiStructure {
    /// SMBIOS string references are 1-based indices into the string set, with
    /// 0 meaning "not set".
    fn text(&self, offset: usize) -> Option<String> {
        let index = *self.data.get(offset)? as usize;
        let value = self.strings.get(index.checked_sub(1)?)?.trim();
        // Firmware that has nothing to say still fills the field in.
        if value.is_empty()
            || value.contains('\0')
            || ["Not Specified", "To Be Filled By O.E.M.", "None", "Unknown"].contains(&value)
        {
            return None;
        }
        Some(value.to_owned())
    }

    fn word(&self, offset: usize) -> Option<u64> {
        let bytes = self.data.get(offset..offset + 2)?;
        Some(u16::from_le_bytes([bytes[0], bytes[1]]) as u64)
    }
}

/// Split the raw SMBIOS table into structures.
///
/// Each structure is a header, a formatted area whose length the header gives,
/// and a double-NUL-terminated string set. The table is exactly what firmware
/// wrote, so a malformed length ends the walk rather than indexing past it.
fn parse_dmi(data: &[u8]) -> Vec<DmiStructure> {
    let mut structures = Vec::new();
    let mut offset = 0usize;
    while offset + 4 <= data.len() {
        let kind = data[offset];
        let length = data[offset + 1] as usize;
        if length < 4 || offset + length > data.len() {
            break;
        }
        let formatted = data[offset..offset + length].to_vec();
        let mut cursor = offset + length;
        let mut strings = Vec::new();
        let mut current = Vec::new();
        while cursor < data.len() {
            if data[cursor] == 0 {
                if current.is_empty() {
                    cursor += 1;
                    break;
                }
                strings.push(String::from_utf8_lossy(&current).into_owned());
                current.clear();
            } else {
                current.push(data[cursor]);
            }
            cursor += 1;
        }
        structures.push(DmiStructure {
            kind,
            data: formatted,
            strings,
        });
        // End-of-table marker.
        if kind == 127 {
            break;
        }
        offset = cursor;
    }
    structures
}

fn read_dmi(root: &Path) -> Vec<DmiStructure> {
    // Root-only on every distribution, which is why the sysfs DMI attributes
    // are read separately and this is treated as a bonus.
    fs::read(root.join("sys/firmware/dmi/tables/DMI"))
        .map(|data| parse_dmi(&data))
        .unwrap_or_default()
}

/// SMBIOS fields that `/sys/class/dmi/id` does not expose.
///
/// The kernel publishes a handful of DMI attributes as files; the memory
/// modules, the processor's socket and speed ceiling, and the chassis asset
/// tag exist only in the raw table. Serial numbers and the system UUID are in
/// there too and are deliberately not read.
fn dmi_smbios(structures: &[DmiStructure]) -> serde_json::Map<String, Value> {
    let mut smbios = serde_json::Map::new();
    if let Some(chassis) = structures.iter().find(|item| item.kind == 3) {
        insert_string(&mut smbios, "chassis_asset", chassis.text(8));
        insert_string(&mut smbios, "chassis_sku", chassis.text(0x15));
    }
    if let Some(processor) = structures.iter().find(|item| item.kind == 4) {
        insert_string(&mut smbios, "processor_socket_prefix", processor.text(4));
        insert_string(&mut smbios, "processor_manufacturer", processor.text(7));
        insert_string(&mut smbios, "processor_version", processor.text(0x10));
        insert_string(&mut smbios, "processor_asset", processor.text(0x21));
        insert_string(&mut smbios, "processor_part", processor.text(0x22));
        for (key, offset) in [
            ("processor_max_speed", 0x14),
            ("processor_current_speed", 0x16),
        ] {
            if let Some(speed) = processor.word(offset).filter(|speed| *speed > 0) {
                smbios.insert(key.into(), Value::from(speed));
            }
        }
    }
    // A machine has one memory profile but many modules; the first populated
    // one names the part the guest reports.
    if let Some(memory) = structures
        .iter()
        .filter(|item| item.kind == 17)
        .find(|item| item.word(0x0C).is_some_and(|size| size > 0))
    {
        insert_string(&mut smbios, "memory_manufacturer", memory.text(0x17));
        insert_string(&mut smbios, "memory_asset", memory.text(0x19));
        insert_string(&mut smbios, "memory_part", memory.text(0x1A));
        insert_string(&mut smbios, "memory_locator_prefix", memory.text(0x10));
        insert_string(&mut smbios, "memory_bank", memory.text(0x11));
        // Offset 0x15 is the rated speed; 0x20 is what it is clocked at.
        if let Some(speed) = memory
            .word(0x20)
            .filter(|speed| *speed > 0)
            .or_else(|| memory.word(0x15))
            .filter(|speed| *speed > 0)
        {
            smbios.insert("memory_speed".into(), Value::from(speed));
        }
    }
    smbios
}

/// Every populated memory slot, for the same reason the other lists are kept.
fn dmi_memory_devices(structures: &[DmiStructure]) -> Vec<Value> {
    let mut devices = Vec::new();
    for memory in structures.iter().filter(|item| item.kind == 17) {
        // Size 0 marks an empty slot. 0x7FFF means "see the 32-bit extended
        // size at 0x1C", which is how modules of 32GiB and above are reported.
        let size = memory.word(0x0C).unwrap_or(0);
        let mut item = serde_json::Map::new();
        insert_string(&mut item, "locator", memory.text(0x10));
        insert_string(&mut item, "bank", memory.text(0x11));
        if size == 0 {
            item.insert("populated".into(), Value::Bool(false));
            devices.push(Value::Object(item));
            continue;
        }
        item.insert("populated".into(), Value::Bool(true));
        let megabytes = if size == 0x7FFF {
            memory
                .data
                .get(0x1C..0x20)
                .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("fixed width")) as u64)
                .unwrap_or(0)
        } else if size & 0x8000 != 0 {
            // Bit 15 set means the value is in kilobytes.
            (size & 0x7FFF) / 1024
        } else {
            size
        };
        if megabytes > 0 {
            item.insert("size_mb".into(), Value::from(megabytes));
        }
        for (key, offset) in [("rated_speed_mts", 0x15), ("configured_speed_mts", 0x20)] {
            if let Some(speed) = memory.word(offset).filter(|speed| *speed > 0) {
                item.insert(key.into(), Value::from(speed));
            }
        }
        insert_string(&mut item, "manufacturer", memory.text(0x17));
        insert_string(&mut item, "part", memory.text(0x1A));
        if let Some(kind) = memory.data.get(0x12) {
            item.insert("memory_type".into(), Value::from(*kind));
        }
        devices.push(Value::Object(item));
    }
    devices
}

/// ACPI header identity, read from the table the host's own firmware wrote.
///
/// DSDT is preferred because every x86 firmware emits one and OEMs brand it;
/// FACP is the fallback. The fields are at fixed offsets in the 36-byte ACPI
/// header, so a truncated table is skipped rather than parsed into garbage.
fn host_acpi(root: &Path) -> serde_json::Map<String, Value> {
    let tables = root.join("sys/firmware/acpi/tables");
    let mut acpi = serde_json::Map::new();
    let data = ["DSDT", "FACP"]
        .into_iter()
        .find_map(|name| fs::read(tables.join(name)).ok())
        .filter(|data| data.len() >= 36);
    let Some(data) = data else {
        return acpi;
    };
    // These fields are fixed-width and padded, with spaces by some firmware
    // and NULs by others; AMI writes "A M I" followed by NULs. Trimming only
    // whitespace dropped the field on every such host.
    let text = |range: std::ops::Range<usize>| {
        let value = String::from_utf8_lossy(&data[range])
            .trim_matches(|character: char| character == '\0' || character.is_whitespace())
            .to_owned();
        (!value.is_empty() && !value.contains('\0')).then_some(value)
    };
    let number = |start: usize| {
        u32::from_le_bytes(
            data[start..start + 4]
                .try_into()
                .expect("fixed header width"),
        )
    };
    insert_string(&mut acpi, "oem_id", text(10..16));
    insert_string(&mut acpi, "oem_table_id", text(16..24));
    acpi.insert("oem_revision".into(), Value::from(number(24)));
    insert_string(&mut acpi, "creator_id", text(28..32));
    acpi.insert("creator_revision".into(), Value::from(number(32)));
    acpi
}

fn sorted_dir(path: &Path) -> Vec<PathBuf> {
    let mut entries: Vec<PathBuf> = fs::read_dir(path)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect();
    entries.sort();
    entries
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_owned()
}

fn hex_id(path: &Path) -> Option<u64> {
    let value = host_string(path)?;
    u64::from_str_radix(value.trim_start_matches("0x"), 16).ok()
}

/// PCI and USB identifiers are universally written in hex; printing 32902 for
/// 0x8086 makes an inventory that nobody can read against lspci or lsusb.
fn hex_value(value: u64, digits: usize) -> Value {
    Value::String(format!("0x{value:0digits$x}"))
}

fn hex_field(item: &Value, key: &str) -> Option<u64> {
    let value = item.get(key)?.as_str()?;
    u64::from_str_radix(value.trim_start_matches("0x"), 16).ok()
}

fn number(path: &Path) -> Option<u64> {
    host_string(path)?.parse().ok()
}

/// Decode the fields of an EDID block that describe the panel.
///
/// The serial number in bytes 12-15 and the 0xFF descriptor are read past on
/// purpose: they identify one physical monitor, so the profile derives a
/// serial from the seed instead.
fn parse_edid(edid: &[u8]) -> Option<serde_json::Map<String, Value>> {
    // A disconnected connector reads back empty, and every real EDID opens
    // with the same fixed header.
    if edid.len() < 128 || edid[0..8] != [0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00] {
        return None;
    }
    // EDID packs the manufacturer as three 5-bit letters, big-endian, in
    // bytes 8-9; 'A' is 1.
    let packed = u16::from_be_bytes([edid[8], edid[9]]);
    let vendor: String = (0..3)
        .map(|index| (b'A' - 1 + ((packed >> (10 - index * 5)) & 0x1f) as u8) as char)
        .collect();
    if !vendor
        .chars()
        .all(|character| character.is_ascii_uppercase())
    {
        return None;
    }
    let mut display = serde_json::Map::new();
    display.insert("vendor".into(), Value::String(vendor));
    display.insert(
        "product_id".into(),
        Value::from(u16::from_le_bytes([edid[10], edid[11]])),
    );
    // Week 0 and year 0 mean the monitor did not record a build date.
    if edid[16] > 0 && edid[16] <= 54 {
        display.insert("manufacture_week".into(), Value::from(edid[16]));
    }
    if edid[17] > 0 {
        display.insert(
            "manufacture_year".into(),
            Value::from(1990 + edid[17] as u64),
        );
    }
    display.insert(
        "edid_version".into(),
        Value::String(format!("{}.{}", edid[18], edid[19])),
    );
    // The four 18-byte descriptors at 54 hold the monitor name (0xFC) and the
    // preferred timing, whose resolution is split across nibbles.
    for block in edid[54..126].chunks(18) {
        if block[0..3] == [0, 0, 0] && block[3] == 0xFC {
            let name = String::from_utf8_lossy(&block[5..18])
                .trim_end_matches(['\n', ' '])
                .trim()
                .to_owned();
            if !name.is_empty() && !name.contains('\0') {
                display.insert("name".into(), Value::String(name));
            }
        } else if block[0..2] != [0, 0] && !display.contains_key("xres") {
            let xres = block[2] as u64 | (((block[4] as u64) & 0xf0) << 4);
            let yres = block[5] as u64 | (((block[7] as u64) & 0xf0) << 4);
            // The refresh rate is not stored; it is the pixel clock over the
            // total blanked frame, which is what a guest computes when it
            // reports a mode.
            let clock = u16::from_le_bytes([block[0], block[1]]) as u64 * 10_000;
            let htotal = xres + (block[3] as u64 | (((block[4] as u64) & 0x0f) << 8));
            let vtotal = yres + (block[6] as u64 | (((block[7] as u64) & 0x0f) << 8));
            if xres > 0 && yres > 0 {
                display.insert("xres".into(), Value::from(xres));
                display.insert("yres".into(), Value::from(yres));
                if htotal > 0 && vtotal > 0 && clock > 0 {
                    let rate = (clock + htotal * vtotal / 2) / (htotal * vtotal);
                    display.insert("refresh_rate".into(), Value::from(rate));
                }
            }
        }
    }
    // Bytes 21 and 22 are the screen size in whole centimetres.
    let (width_mm, height_mm) = (edid[21] as u64 * 10, edid[22] as u64 * 10);
    if width_mm > 0 && height_mm > 0 {
        display.insert("width_mm".into(), Value::from(width_mm));
        display.insert("height_mm".into(), Value::from(height_mm));
    }
    Some(display)
}

fn host_displays(root: &Path) -> Vec<Value> {
    let mut displays = Vec::new();
    for connector in sorted_dir(&root.join("sys/class/drm")) {
        let Ok(edid) = fs::read(connector.join("edid")) else {
            continue;
        };
        let Some(mut display) = parse_edid(&edid) else {
            continue;
        };
        display.insert("connector".into(), Value::String(file_name(&connector)));
        display.insert(
            "status".into(),
            Value::String(host_string(&connector.join("status")).unwrap_or_default()),
        );
        displays.push(Value::Object(display));
    }
    displays
}

fn host_block_devices(root: &Path) -> Vec<Value> {
    let mut devices = Vec::new();
    for path in sorted_dir(&root.join("sys/block")) {
        let name = file_name(&path);
        // Virtual devices describe the host's storage stack, not its hardware.
        if ["loop", "ram", "zram", "dm-", "md"]
            .iter()
            .any(|prefix| name.starts_with(prefix))
        {
            continue;
        }
        let device = path.join("device");
        let mut item = serde_json::Map::new();
        item.insert("name".into(), Value::String(name.clone()));
        item.insert(
            "kind".into(),
            Value::String(
                if name.starts_with("sr") {
                    "optical"
                } else {
                    "disk"
                }
                .into(),
            ),
        );
        insert_string(&mut item, "vendor", host_string(&device.join("vendor")));
        insert_string(&mut item, "model", host_string(&device.join("model")));
        insert_string(&mut item, "revision", host_string(&device.join("rev")));
        // Sysfs reports capacity in 512-byte sectors regardless of the
        // device's own block size.
        if let Some(sectors) = number(&path.join("size")) {
            item.insert("size_bytes".into(), Value::from(sectors * 512));
        }
        if let Some(removable) = number(&path.join("removable")) {
            item.insert("removable".into(), Value::from(removable == 1));
        }
        if let Some(rotational) = number(&path.join("queue/rotational")) {
            item.insert("rotational".into(), Value::from(rotational == 1));
        }
        devices.push(Value::Object(item));
    }
    devices
}

fn host_pci_devices(root: &Path) -> Vec<Value> {
    let mut devices = Vec::new();
    for path in sorted_dir(&root.join("sys/bus/pci/devices")) {
        let mut item = serde_json::Map::new();
        item.insert("slot".into(), Value::String(file_name(&path)));
        for (key, file, digits) in [
            ("vendor_id", "vendor", 4),
            ("device_id", "device", 4),
            ("subsystem_vendor_id", "subsystem_vendor", 4),
            ("subsystem_id", "subsystem_device", 4),
            ("class", "class", 6),
        ] {
            if let Some(value) = hex_id(&path.join(file)) {
                item.insert(key.into(), hex_value(value, digits));
            }
        }
        if let Ok(driver) = fs::read_link(path.join("driver")) {
            item.insert("driver".into(), Value::String(file_name(&driver)));
        }
        devices.push(Value::Object(item));
    }
    devices
}

fn host_usb_devices(root: &Path) -> Vec<Value> {
    let mut devices = Vec::new();
    for path in sorted_dir(&root.join("sys/bus/usb/devices")) {
        // Interfaces appear beside devices in this directory; only devices
        // carry an idVendor.
        let Some(vendor) = hex_id(&path.join("idVendor")) else {
            continue;
        };
        let mut item = serde_json::Map::new();
        item.insert("path".into(), Value::String(file_name(&path)));
        item.insert("vendor_id".into(), hex_value(vendor, 4));
        if let Some(product) = hex_id(&path.join("idProduct")) {
            item.insert("product_id".into(), hex_value(product, 4));
        }
        if let Some(bcd) = hex_id(&path.join("bcdDevice")) {
            item.insert("bcd_device".into(), hex_value(bcd, 4));
        }
        insert_string(
            &mut item,
            "manufacturer",
            host_string(&path.join("manufacturer")),
        );
        insert_string(&mut item, "product", host_string(&path.join("product")));
        devices.push(Value::Object(item));
    }
    devices
}

/// Network interfaces, by model rather than by address.
///
/// The MAC is the one value here that identifies this machine, so it is left
/// out; the guest's MAC is derived from the seed.
fn host_network_devices(root: &Path) -> Vec<Value> {
    let mut devices = Vec::new();
    for path in sorted_dir(&root.join("sys/class/net")) {
        let name = file_name(&path);
        // A host that runs containers has dozens of veth and bridge
        // interfaces. Only an interface backed by a real device has a
        // `device` link, and only those describe the hardware.
        if name == "lo" || !path.join("device").exists() {
            continue;
        }
        let mut item = serde_json::Map::new();
        item.insert("name".into(), Value::String(name));
        for (key, file) in [
            ("vendor_id", "device/vendor"),
            ("device_id", "device/device"),
        ] {
            if let Some(value) = hex_id(&path.join(file)) {
                item.insert(key.into(), Value::from(value));
            }
        }
        if let Ok(driver) = fs::read_link(path.join("device/driver")) {
            item.insert("driver".into(), Value::String(file_name(&driver)));
        }
        insert_string(&mut item, "operstate", host_string(&path.join("operstate")));
        if let Some(speed) = host_string(&path.join("speed")).and_then(|v| v.parse::<i64>().ok())
            && speed > 0
        {
            item.insert("speed_mbps".into(), Value::from(speed));
        }
        devices.push(Value::Object(item));
    }
    devices
}

fn host_thermal_zones(root: &Path) -> Vec<Value> {
    let mut zones = Vec::new();
    for path in sorted_dir(&root.join("sys/class/thermal")) {
        if !file_name(&path).starts_with("thermal_zone") {
            continue;
        }
        let millidegrees = |path: PathBuf| -> Option<i64> {
            host_string(&path)?
                .parse::<i64>()
                .ok()
                .map(|value| value / 1000)
        };
        let mut item = serde_json::Map::new();
        item.insert("zone".into(), Value::String(file_name(&path)));
        insert_string(&mut item, "type", host_string(&path.join("type")));
        if let Some(temperature) = millidegrees(path.join("temp")) {
            item.insert("temperature_celsius".into(), Value::from(temperature));
        }
        for index in 0..16 {
            let Some(kind) = host_string(&path.join(format!("trip_point_{index}_type"))) else {
                continue;
            };
            let key = match kind.as_str() {
                "passive" => "passive_celsius",
                "critical" => "critical_celsius",
                _ => continue,
            };
            // A disabled trip point reads back as -274000, below absolute
            // zero; a guest would read that as a machine with no cooling
            // policy at all.
            if !item.contains_key(key)
                && let Some(value) = millidegrees(path.join(format!("trip_point_{index}_temp")))
                && (1..=200).contains(&value)
            {
                item.insert(key.into(), Value::from(value));
            }
        }
        zones.push(Value::Object(item));
    }
    zones
}

fn host_fans(root: &Path) -> Vec<Value> {
    let mut fans = Vec::new();
    for monitor in sorted_dir(&root.join("sys/class/hwmon")) {
        let chip = host_string(&monitor.join("name"));
        for index in 1..16 {
            let Some(rpm) = number(&monitor.join(format!("fan{index}_input"))) else {
                continue;
            };
            let mut item = serde_json::Map::new();
            item.insert("hwmon".into(), Value::String(file_name(&monitor)));
            insert_string(&mut item, "chip", chip.clone());
            insert_string(
                &mut item,
                "label",
                host_string(&monitor.join(format!("fan{index}_label"))),
            );
            item.insert("rpm".into(), Value::from(rpm));
            fans.push(Value::Object(item));
        }
    }
    fans
}

/// Everything the host will tell us about its hardware.
///
/// The profile below picks one display, one disk and one subsystem ID out of
/// this, because that is what a single emulated machine can carry. The full
/// lists stay in the output so the choice can be revisited without going back
/// to the machine -- and so a second look can tell "the host has one monitor"
/// from "we only looked at the first one".
fn host_inventory(root: &Path) -> serde_json::Map<String, Value> {
    let mut inventory = serde_json::Map::new();
    inventory.insert("displays".into(), Value::Array(host_displays(root)));
    inventory.insert(
        "block_devices".into(),
        Value::Array(host_block_devices(root)),
    );
    inventory.insert("pci_devices".into(), Value::Array(host_pci_devices(root)));
    inventory.insert("usb_devices".into(), Value::Array(host_usb_devices(root)));
    inventory.insert(
        "network_devices".into(),
        Value::Array(host_network_devices(root)),
    );
    inventory.insert(
        "thermal_zones".into(),
        Value::Array(host_thermal_zones(root)),
    );
    inventory.insert("fans".into(), Value::Array(host_fans(root)));
    inventory
}

fn field<'a>(item: &'a Value, key: &str) -> Option<&'a Value> {
    item.get(key).filter(|value| !value.is_null())
}

/// QEMU's fallback subsystem IDs are a Red Hat/QEMU pair a guest can read off
/// any device, so the profile replaces them with the host's. The host bridge
/// is preferred: it is the device a real board is guaranteed to brand.
fn pci_defaults(inventory: &serde_json::Map<String, Value>) -> serde_json::Map<String, Value> {
    let devices = inventory["pci_devices"].as_array().expect("array");
    let usable = |device: &&Value| {
        hex_field(device, "subsystem_vendor_id").is_some_and(|value| value > 0)
            && hex_field(device, "subsystem_id").is_some()
    };
    let chosen = devices
        .iter()
        .find(|device| device["slot"] == "0000:00:00.0" && usable(device))
        .or_else(|| devices.iter().find(usable));
    let mut pci = serde_json::Map::new();
    if let Some(device) = chosen {
        // QEMU's properties take numbers; only the inventory is written in hex.
        for key in ["subsystem_vendor_id", "subsystem_id"] {
            if let Some(value) = hex_field(device, key) {
                pci.insert(key.into(), Value::from(value));
            }
        }
        pci.insert("source_slot".into(), device["slot"].clone());
    }
    pci
}

/// The emulated machine gets one disk, one optical drive and one monitor.
///
/// The connected display is preferred over a stale EDID on an unplugged
/// connector, and a fixed disk over removable media.
fn device_descriptors(
    inventory: &serde_json::Map<String, Value>,
    seed_hash: &str,
) -> serde_json::Map<String, Value> {
    let blocks = inventory["block_devices"].as_array().expect("array");
    let mut storage = serde_json::Map::new();
    let disk = blocks
        .iter()
        .find(|device| device["kind"] == "disk" && device["removable"] != Value::Bool(true))
        .or_else(|| blocks.iter().find(|device| device["kind"] == "disk"));
    if let Some(disk) = disk {
        insert_string(
            &mut storage,
            "disk_vendor",
            field(disk, "vendor")
                .and_then(Value::as_str)
                .map(str::to_owned),
        );
        insert_string(
            &mut storage,
            "disk_product",
            field(disk, "model")
                .and_then(Value::as_str)
                .map(str::to_owned),
        );
        storage.insert("source_device".into(), disk["name"].clone());
        storage.insert(
            "disk_serial_prefix".into(),
            Value::String(format!("AN-{}", seed_hash[..8].to_uppercase())),
        );
    }
    if let Some(optical) = blocks.iter().find(|device| device["kind"] == "optical") {
        insert_string(
            &mut storage,
            "optical_vendor",
            field(optical, "vendor")
                .and_then(Value::as_str)
                .map(str::to_owned),
        );
        insert_string(
            &mut storage,
            "optical_product",
            field(optical, "model")
                .and_then(Value::as_str)
                .map(str::to_owned),
        );
    }

    let displays = inventory["displays"].as_array().expect("array");
    let mut display = displays
        .iter()
        .find(|display| display["status"] == "connected")
        .or_else(|| displays.first())
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    if !display.is_empty() {
        display.remove("status");
        if let Some(connector) = display.remove("connector") {
            display.insert("source_connector".into(), connector);
        }
        // The monitor's own serial, like the machine's, stays derived: the
        // number in the EDID identifies the panel on the host's desk.
        display.insert(
            "serial".into(),
            Value::String(format!("AN-{}", seed_hash[8..16].to_uppercase())),
        );
    }

    let mut descriptors = serde_json::Map::new();
    if !storage.is_empty() {
        descriptors.insert("storage".into(), Value::Object(storage));
    }
    if !display.is_empty() {
        descriptors.insert("display".into(), Value::Object(display));
    }
    descriptors
}

/// thermal_zone0 is whatever the kernel registered first, which on a desktop
/// board is often an INT3400 policy device idling at room temperature while
/// the CPU package sits at 70C. A guest reading a CPU temperature that never
/// moves has learned something, so prefer the package sensor.
fn sensors(inventory: &serde_json::Map<String, Value>) -> serde_json::Map<String, Value> {
    let zones = inventory["thermal_zones"].as_array().expect("array");
    let plausible = |zone: &&Value| {
        field(zone, "temperature_celsius")
            .and_then(Value::as_i64)
            .is_some_and(|value| (1..=150).contains(&value))
    };
    let chosen = ["x86_pkg_temp", "acpitz"]
        .into_iter()
        .find_map(|kind| {
            zones
                .iter()
                .find(|zone| zone["type"] == kind && plausible(zone))
        })
        .or_else(|| zones.iter().find(plausible));
    let mut sensors = serde_json::Map::new();
    if let Some(zone) = chosen {
        for key in ["temperature_celsius", "passive_celsius", "critical_celsius"] {
            if let Some(value) = field(zone, key) {
                sensors.insert(key.into(), value.clone());
            }
        }
        sensors.insert("source_zone".into(), zone["zone"].clone());
    }
    if let Some(fan) = inventory["fans"]
        .as_array()
        .expect("array")
        .iter()
        .find(|fan| fan["rpm"].as_u64() > Some(0))
    {
        sensors.insert("fan_rpm".into(), fan["rpm"].clone());
    }
    sensors
}

/// Build an analysis profile that mirrors the host's hardware identity.
///
/// The result is an ordinary profile input: the model-level fields come from
/// the host, while the seed still derives the UUID, MAC and serial numbers, so
/// the clone can run beside the machine it was taken from. Every source is
/// optional -- a container with no DMI, or a host whose ACPI tables are
/// root-only, yields a profile with fewer fields rather than an error.
pub fn host_clone(root: &Path, seed: &str) -> Result<Value, ProfileError> {
    if seed.is_empty() || seed.contains('\0') {
        return Err(ProfileError::Seed);
    }
    let seed_hash = hex(&Sha256::digest(seed.as_bytes()));
    let mut analysis = serde_json::Map::new();
    analysis.insert("enabled".into(), Value::Bool(true));
    analysis.insert("profile".into(), Value::String("malware-analysis".into()));
    analysis.insert("identity_seed".into(), Value::String(seed.to_owned()));
    let dmi = read_dmi(root);
    let mut inventory = host_inventory(root);
    inventory.insert(
        "memory_devices".into(),
        Value::Array(dmi_memory_devices(&dmi)),
    );
    let mut smbios = host_smbios(root);
    // The sysfs attributes win where both have the field: they are what the
    // kernel itself reports, and the raw table only fills the gaps.
    for (key, value) in dmi_smbios(&dmi) {
        smbios.entry(key).or_insert(value);
    }
    for (key, value) in [
        ("smbios", smbios),
        ("acpi", host_acpi(root)),
        ("pci", pci_defaults(&inventory)),
        (
            "device_descriptors",
            device_descriptors(&inventory, &seed_hash),
        ),
        ("sensors", sensors(&inventory)),
    ] {
        analysis.insert(key.into(), Value::Object(value));
    }

    let cpuinfo = fs::read_to_string(root.join("proc/cpuinfo")).unwrap_or_default();
    let vcpu = cpuinfo
        .lines()
        .filter(|line| line.starts_with("processor"))
        .count()
        .max(1);
    let memory = fs::read_to_string(root.join("proc/meminfo"))
        .ok()
        .and_then(|text| {
            text.lines()
                .find(|line| line.starts_with("MemTotal:"))?
                .split_whitespace()
                .nth(1)?
                .parse::<u64>()
                .ok()
        })
        .map(|kib| format!("{}GiB", (kib / (1024 * 1024)).max(1)));

    let mut profile = serde_json::Map::new();
    profile.insert("analysis".into(), Value::Object(analysis));
    profile.insert("network".into(), serde_json::json!({"type": "user"}));
    // model-id is what a guest reads as its CPU brand string; the host's own
    // brand is already in smbios.processor_version.
    profile.insert("cpu".into(), Value::String("host,kvm=off".into()));
    profile.insert("vcpu".into(), Value::from(vcpu));
    if let Some(memory) = memory {
        profile.insert("memory".into(), Value::String(memory));
    }
    // ACPI tables are root-only on most distributions, and a container may
    // have no DMI at all. Name the sections that came back empty: silence here
    // otherwise reads as a host that simply has no such hardware.
    let mut unread: Vec<Value> = ["smbios", "acpi", "pci", "device_descriptors", "sensors"]
        .into_iter()
        .filter(|key| {
            profile["analysis"][key]
                .as_object()
                .is_some_and(serde_json::Map::is_empty)
        })
        .map(|key| Value::String(key.into()))
        .collect();
    // The raw SMBIOS table is the other root-only source, and the only one
    // that carries the memory modules and the processor's socket.
    if dmi.is_empty() {
        unread.push(Value::String("dmi".into()));
    }
    // Everything the host reported, so the choices above can be revisited
    // without going back to the machine.
    profile.insert("inventory".into(), Value::Object(inventory));
    profile.insert(
        "source".into(),
        serde_json::json!({
            "kind": "host-clone", "os": "Linux", "method": "sysfs",
            "root": root.display().to_string(), "identity": "derived-from-seed",
            "unavailable": unread,
        }),
    );
    Ok(Value::Object(profile))
}

pub fn host_clone_json(root: &Path, seed: &str) -> Result<String, ProfileError> {
    Ok(serde_json::to_string_pretty(&host_clone(root, seed)?)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Build one SMBIOS structure: a header, a formatted area with the given
    /// bytes placed at their offsets, and the string set.
    fn dmi_structure(
        kind: u8,
        length: usize,
        fields: &[(usize, &[u8])],
        strings: &[&str],
    ) -> Vec<u8> {
        let mut data = vec![0u8; length];
        data[0] = kind;
        data[1] = length as u8;
        for (offset, bytes) in fields {
            data[*offset..*offset + bytes.len()].copy_from_slice(bytes);
        }
        for text in strings {
            data.extend_from_slice(text.as_bytes());
            data.push(0);
        }
        if strings.is_empty() {
            data.push(0);
        }
        data.push(0);
        data
    }

    fn fixture_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "machineemu-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

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

    #[test]
    fn host_clone_mirrors_model_identity_and_derives_serials() {
        let root = fixture_root("host-clone");
        let dmi = root.join("sys/class/dmi/id");
        std::fs::create_dir_all(&dmi).unwrap();
        for (file, value) in [
            ("sys_vendor", "LENOVO"),
            ("product_name", "20XW00BTGE"),
            ("bios_vendor", "LENOVO"),
            ("bios_version", "N32ET75W"),
            // Never cloned: these tie the machine to its owner.
            ("product_serial", "PF2ABCDE"),
            ("product_uuid", "3f2504e0-4f89-11d3-9a0c-0305e82c3301"),
        ] {
            std::fs::write(dmi.join(file), format!("{value}\n")).unwrap();
        }
        std::fs::create_dir_all(root.join("proc")).unwrap();
        std::fs::write(
            root.join("proc/cpuinfo"),
            "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Core i7\n\nprocessor\t: 1\n",
        )
        .unwrap();
        let tables = root.join("sys/firmware/acpi/tables");
        std::fs::create_dir_all(&tables).unwrap();
        let mut dsdt = vec![0u8; 36];
        dsdt[0..4].copy_from_slice(b"DSDT");
        dsdt[10..16].copy_from_slice(b"LENOVO");
        // AMI pads this field with NULs rather than spaces.
        dsdt[16..24].copy_from_slice(b"TP-N32\0\0");
        dsdt[24..28].copy_from_slice(&1u32.to_le_bytes());
        dsdt[28..32].copy_from_slice(b"ACPI");
        std::fs::write(tables.join("DSDT"), &dsdt).unwrap();
        // A monitor's EDID: fixed header, "DEL" packed as three 5-bit
        // letters, a 1920x1080@60 preferred timing, a name descriptor, and a
        // serial descriptor that must not be copied.
        let connector = root.join("sys/class/drm/card0-DP-1");
        std::fs::create_dir_all(&connector).unwrap();
        std::fs::write(connector.join("status"), "connected\n").unwrap();
        let mut edid = vec![0u8; 128];
        edid[0..8].copy_from_slice(&[0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]);
        edid[8..10].copy_from_slice(&0x10ACu16.to_be_bytes());
        edid[10..12].copy_from_slice(&0xD12Du16.to_le_bytes());
        edid[16] = 18;
        edid[17] = 32; // 2022
        edid[18] = 1;
        edid[19] = 4;
        edid[21] = 80;
        edid[22] = 33;
        let timing = &mut edid[54..72];
        timing[0..2].copy_from_slice(&14850u16.to_le_bytes());
        timing[2] = (1920u16 & 0xff) as u8;
        timing[3] = (280u16 & 0xff) as u8;
        timing[4] = 0x71;
        timing[5] = (1080u16 & 0xff) as u8;
        timing[6] = 45;
        timing[7] = 0x40;
        edid[72..76].copy_from_slice(&[0, 0, 0, 0xFC]);
        edid[77..90].copy_from_slice(b"DELL S3422DWG");
        edid[90..94].copy_from_slice(&[0, 0, 0, 0xFF]);
        edid[95..102].copy_from_slice(b"2Y4XS63");
        std::fs::write(connector.join("edid"), &edid).unwrap();
        // A second monitor, unplugged but still cached by the driver, sorting
        // ahead of the connected one.
        let stale = root.join("sys/class/drm/card0-DP-0");
        std::fs::create_dir_all(&stale).unwrap();
        std::fs::write(stale.join("status"), "disconnected\n").unwrap();
        let mut second = edid.clone();
        second[8..10].copy_from_slice(&0x0472u16.to_be_bytes()); // ACR
        std::fs::write(stale.join("edid"), &second).unwrap();

        // Two fixed disks, a USB stick and an optical drive.
        for (name, model, removable) in [
            ("sda", "Samsung SSD 990 PRO 4TB", "0"),
            ("sdb", "CT4000P3PSSD8", "0"),
            ("sdc", "Cruzer Blade", "1"),
            ("sr0", "DVD-ROM SH-116", "1"),
        ] {
            let device = root.join("sys/block").join(name).join("device");
            std::fs::create_dir_all(&device).unwrap();
            std::fs::write(device.join("model"), model).unwrap();
            std::fs::write(device.join("vendor"), "ATA").unwrap();
            std::fs::write(device.parent().unwrap().join("removable"), removable).unwrap();
            std::fs::write(device.parent().unwrap().join("size"), "7814037168").unwrap();
        }
        // Virtual devices are not hardware and must not be listed.
        std::fs::create_dir_all(root.join("sys/block/loop0")).unwrap();

        // thermal_zone0 is a policy device idling at room temperature; the
        // package sensor is the one a guest would recognize.
        for (zone, kind, temp) in [
            ("thermal_zone0", "INT3400", 20000),
            ("thermal_zone1", "x86_pkg_temp", 71000),
        ] {
            let path = root.join("sys/class/thermal").join(zone);
            std::fs::create_dir_all(&path).unwrap();
            std::fs::write(path.join("type"), kind).unwrap();
            std::fs::write(path.join("temp"), temp.to_string()).unwrap();
        }
        let package = root.join("sys/class/thermal/thermal_zone1");
        std::fs::write(package.join("trip_point_0_type"), "critical").unwrap();
        std::fs::write(package.join("trip_point_0_temp"), "100000").unwrap();
        std::fs::write(package.join("trip_point_1_type"), "passive").unwrap();
        // A disabled trip point, which must not reach the profile.
        std::fs::write(package.join("trip_point_1_temp"), "-274000").unwrap();

        let device = root.join("sys/bus/pci/devices/0000:00:00.0");
        std::fs::create_dir_all(&device).unwrap();
        std::fs::write(device.join("subsystem_vendor"), "0x17aa\n").unwrap();
        std::fs::write(device.join("subsystem_device"), "0x2280\n").unwrap();

        let profile = host_clone(&root, "seed").unwrap();
        let analysis = &profile["analysis"];
        assert_eq!(analysis["smbios"]["system_manufacturer"], "LENOVO");
        assert_eq!(analysis["smbios"]["bios_version"], "N32ET75W");
        assert_eq!(analysis["smbios"]["processor_version"], "Core i7");
        assert_eq!(analysis["acpi"]["oem_id"], "LENOVO");
        assert_eq!(analysis["acpi"]["oem_table_id"], "TP-N32");
        assert_eq!(analysis["acpi"]["creator_id"], "ACPI");
        assert_eq!(analysis["acpi"]["oem_table_id"], "TP-N32");
        // QEMU's properties take numbers; the inventory is written the way
        // lspci and lsusb write it.
        assert_eq!(analysis["pci"]["subsystem_vendor_id"], 0x17aa);
        assert_eq!(
            profile["inventory"]["pci_devices"][0]["subsystem_vendor_id"],
            "0x17aa"
        );
        // Everything the host reported is kept, and the profile picks from it:
        // the connected monitor, and a fixed disk over removable media.
        let inventory = &profile["inventory"];
        assert_eq!(inventory["displays"].as_array().unwrap().len(), 2);
        assert_eq!(inventory["block_devices"].as_array().unwrap().len(), 4);
        assert_eq!(inventory["pci_devices"].as_array().unwrap().len(), 1);
        assert_eq!(inventory["thermal_zones"].as_array().unwrap().len(), 2);
        let storage = &analysis["device_descriptors"]["storage"];
        assert_eq!(storage["disk_product"], "Samsung SSD 990 PRO 4TB");
        assert_eq!(storage["source_device"], "sda");
        assert_eq!(storage["optical_product"], "DVD-ROM SH-116");
        let display = &analysis["device_descriptors"]["display"];
        assert_eq!(display["source_connector"], "card0-DP-1");
        assert_eq!(display["vendor"], "DEL");
        assert_eq!(display["product_id"], 0xD12D);
        assert_eq!(display["manufacture_week"], 18);
        assert_eq!(display["manufacture_year"], 2022);
        assert_eq!(display["edid_version"], "1.4");
        assert_eq!(display["name"], "DELL S3422DWG");
        assert_eq!(display["xres"], 1920);
        assert_eq!(display["yres"], 1080);
        assert_eq!(display["refresh_rate"], 60);
        assert_eq!(display["width_mm"], 800);
        assert_eq!(display["height_mm"], 330);
        let sensors = &analysis["sensors"];
        assert_eq!(sensors["temperature_celsius"], 71);
        assert_eq!(sensors["critical_celsius"], 100);
        assert!(sensors.get("passive_celsius").is_none());
        assert_eq!(profile["vcpu"], 2);
        // The host's serial and UUID must not reach the profile in any form.
        let text = serde_json::to_string(&profile).unwrap();
        assert!(!text.contains("PF2ABCDE"));
        assert!(!text.contains("3f2504e0"));
        // Nor may the monitor's own serial, from the 0xFF descriptor.
        assert!(!text.contains("2Y4XS63"));

        // The clone is an ordinary profile input: it validates, and the
        // identity it resolves to is the seed's, not the host's.
        let validated = validate_json(&text).unwrap();
        let validated: Value = serde_json::from_str(&validated).unwrap();
        assert_eq!(validated["identity"]["uuid"], identity("seed").uuid);
        assert_eq!(validated["smbios"]["system_manufacturer"], "LENOVO");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn host_clone_tolerates_a_host_with_nothing_readable() {
        let root = fixture_root("host-clone-empty");
        std::fs::create_dir_all(&root).unwrap();
        let profile = host_clone(&root, "seed").unwrap();
        assert_eq!(profile["analysis"]["smbios"], serde_json::json!({}));
        assert_eq!(profile["vcpu"], 1);
        assert!(validate_json(&serde_json::to_string(&profile).unwrap()).is_ok());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn raw_dmi_table_fills_what_sysfs_does_not_expose() {
        let root = fixture_root("host-clone-dmi");
        let tables = root.join("sys/firmware/dmi/tables");
        std::fs::create_dir_all(&tables).unwrap();
        let mut table = Vec::new();
        table.extend(dmi_structure(
            3,
            0x16,
            &[(8, &[1]), (0x15, &[2])],
            &["CHASSIS-ASSET", "SKU-1"],
        ));
        table.extend(dmi_structure(
            4,
            0x30,
            &[
                (4, &[1]),
                (7, &[2]),
                (0x10, &[3]),
                (0x14, &5400u16.to_le_bytes()),
                (0x16, &3997u16.to_le_bytes()),
                (0x22, &[4]),
            ],
            &[
                "LGA1700",
                "Intel(R) Corporation",
                "13th Gen Intel(R) Core(TM) i7-13700K",
                // Firmware that has nothing to say still fills the field in.
                "To Be Filled By O.E.M.",
            ],
        ));
        table.extend(dmi_structure(
            17,
            0x54,
            &[
                // 0x7FFF means "read the 32-bit size at 0x1C", which is how a
                // module of 32GiB is reported.
                (0x0C, &0x7FFFu16.to_le_bytes()),
                (0x10, &[1]),
                (0x11, &[2]),
                (0x12, &[26]),
                (0x15, &3200u16.to_le_bytes()),
                (0x17, &[3]),
                (0x18, &[4]),
                (0x1A, &[5]),
                (0x1C, &32768u32.to_le_bytes()),
                (0x20, &3200u16.to_le_bytes()),
            ],
            &[
                "DIMM 0",
                "P0 CHANNEL A",
                "Corsair",
                // The module's serial, which must not be copied.
                "DEADBEEF01",
                "CMK32GX4M2E3200C16",
            ],
        ));
        table.extend(dmi_structure(17, 0x54, &[(0x10, &[1])], &["DIMM 1"]));
        table.extend(dmi_structure(127, 4, &[], &[]));
        std::fs::write(tables.join("DMI"), &table).unwrap();

        let profile = host_clone(&root, "seed").unwrap();
        let smbios = &profile["analysis"]["smbios"];
        assert_eq!(smbios["chassis_asset"], "CHASSIS-ASSET");
        assert_eq!(smbios["chassis_sku"], "SKU-1");
        assert_eq!(smbios["processor_socket_prefix"], "LGA1700");
        assert_eq!(smbios["processor_max_speed"], 5400);
        assert_eq!(smbios["processor_current_speed"], 3997);
        assert_eq!(smbios["memory_manufacturer"], "Corsair");
        assert_eq!(smbios["memory_part"], "CMK32GX4M2E3200C16");
        assert_eq!(smbios["memory_speed"], 3200);
        // "To Be Filled By O.E.M." is not an identity.
        assert!(smbios.get("processor_part").is_none());

        let modules = profile["inventory"]["memory_devices"].as_array().unwrap();
        assert_eq!(modules.len(), 2);
        assert_eq!(modules[0]["locator"], "DIMM 0");
        assert_eq!(modules[0]["size_mb"], 32768);
        assert_eq!(modules[0]["configured_speed_mts"], 3200);
        assert_eq!(modules[0]["populated"], true);
        assert_eq!(modules[1]["populated"], false);
        assert!(
            !serde_json::to_string(&profile)
                .unwrap()
                .contains("DEADBEEF01")
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
