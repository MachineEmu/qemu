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
    let text = |range: std::ops::Range<usize>| {
        let value = String::from_utf8_lossy(&data[range]).trim().to_owned();
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

/// PCI subsystem identity of the host bridge.
///
/// QEMU's fallback subsystem IDs are a Red Hat/QEMU pair that a guest can read
/// off any device, so the profile replaces them. The host bridge is the device
/// whose subsystem IDs a real board is guaranteed to carry; devices that report
/// 0000 are skipped because that is the same tell as the default.
fn host_pci(root: &Path) -> serde_json::Map<String, Value> {
    let devices = root.join("sys/bus/pci/devices");
    let mut pci = serde_json::Map::new();
    let mut paths: Vec<PathBuf> = fs::read_dir(&devices)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect();
    paths.sort();
    let hex_id = |path: &Path| -> Option<u64> {
        let value = host_string(path)?;
        u64::from_str_radix(value.trim_start_matches("0x"), 16).ok()
    };
    for path in paths {
        let vendor = hex_id(&path.join("subsystem_vendor"));
        let device = hex_id(&path.join("subsystem_device"));
        if let (Some(vendor), Some(device)) = (vendor, device)
            && vendor != 0
        {
            pci.insert("subsystem_vendor_id".into(), Value::from(vendor));
            pci.insert("subsystem_id".into(), Value::from(device));
            break;
        }
    }
    pci
}

/// Storage and display strings the guest can read back from its own devices.
///
/// Disk serials are per-machine and stay derived from the seed; only the
/// vendor/product strings are cloned. EDID is parsed for the monitor's vendor,
/// name and physical size, which is what a guest compares against its reported
/// display.
fn host_device_descriptors(root: &Path, seed_hash: &str) -> serde_json::Map<String, Value> {
    let mut storage = serde_json::Map::new();
    let block = root.join("sys/block");
    let mut names: Vec<PathBuf> = fs::read_dir(&block)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect();
    names.sort();
    for path in &names {
        let device = path.join("device");
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("");
        let vendor = host_string(&device.join("vendor"));
        let model = host_string(&device.join("model"));
        if name.starts_with("sr") {
            insert_string(&mut storage, "optical_vendor", vendor);
            insert_string(&mut storage, "optical_product", model);
        } else if !storage.contains_key("disk_product")
            && (name.starts_with("sd") || name.starts_with("nvme"))
        {
            // NVMe exposes no vendor string, only a model; leaving the vendor
            // absent is better than inventing one the guest could contradict.
            insert_string(&mut storage, "disk_vendor", vendor);
            insert_string(&mut storage, "disk_product", model);
        }
    }
    if storage.contains_key("disk_product") {
        storage.insert(
            "disk_serial_prefix".into(),
            Value::String(format!("AN-{}", seed_hash[..8].to_uppercase())),
        );
    }

    let mut display = serde_json::Map::new();
    let drm = root.join("sys/class/drm");
    let mut cards: Vec<PathBuf> = fs::read_dir(&drm)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect();
    cards.sort();
    for card in cards {
        let Ok(edid) = fs::read(card.join("edid")) else {
            continue;
        };
        if edid.len() < 128 {
            continue;
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
            continue;
        }
        display.insert("vendor".into(), Value::String(vendor));
        // The four 18-byte descriptors at 54 hold the monitor name (0xFC) and
        // the preferred timing, whose resolution is split across nibbles.
        for block in edid[54..126].chunks(18) {
            if block[0..3] == [0, 0, 0] && block[3] == 0xFC {
                let name = String::from_utf8_lossy(&block[5..18])
                    .trim_end_matches(['\n', ' '])
                    .trim()
                    .to_owned();
                if !name.is_empty() && !name.contains('\0') {
                    display.insert("name".into(), Value::String(name));
                }
            } else if block[0..2] != [0, 0] {
                let xres = block[2] as u64 | (((block[4] as u64) & 0xf0) << 4);
                let yres = block[5] as u64 | (((block[7] as u64) & 0xf0) << 4);
                if xres > 0 && yres > 0 && !display.contains_key("xres") {
                    display.insert("xres".into(), Value::from(xres));
                    display.insert("yres".into(), Value::from(yres));
                }
            }
        }
        let (width_mm, height_mm) = (edid[21] as u64 * 10, edid[22] as u64 * 10);
        if width_mm > 0 && height_mm > 0 {
            display.insert("width_mm".into(), Value::from(width_mm));
            display.insert("height_mm".into(), Value::from(height_mm));
        }
        break;
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

/// Thermal and fan readings, which a guest uses to tell a machine with a
/// cooling system from one without.
fn host_sensors(root: &Path) -> serde_json::Map<String, Value> {
    let mut sensors = serde_json::Map::new();
    let zone = root.join("sys/class/thermal/thermal_zone0");
    let millidegrees = |path: PathBuf| -> Option<i64> {
        host_string(&path)?
            .parse::<i64>()
            .ok()
            .map(|value| value / 1000)
    };
    if let Some(temperature) = millidegrees(zone.join("temp")) {
        sensors.insert("temperature_celsius".into(), Value::from(temperature));
    }
    for index in 0..16 {
        let Some(kind) = host_string(&zone.join(format!("trip_point_{index}_type"))) else {
            continue;
        };
        let key = match kind.as_str() {
            "passive" => "passive_celsius",
            "critical" => "critical_celsius",
            _ => continue,
        };
        if !sensors.contains_key(key)
            && let Some(value) = millidegrees(zone.join(format!("trip_point_{index}_temp")))
        {
            sensors.insert(key.into(), Value::from(value));
        }
    }
    let hwmon = root.join("sys/class/hwmon");
    let mut monitors: Vec<PathBuf> = fs::read_dir(&hwmon)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect();
    monitors.sort();
    'outer: for monitor in monitors {
        for index in 1..8 {
            if let Some(rpm) = host_string(&monitor.join(format!("fan{index}_input")))
                .and_then(|value| value.parse::<u64>().ok())
                && rpm > 0
            {
                sensors.insert("fan_rpm".into(), Value::from(rpm));
                break 'outer;
            }
        }
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
    for (key, value) in [
        ("smbios", host_smbios(root)),
        ("acpi", host_acpi(root)),
        ("pci", host_pci(root)),
        (
            "device_descriptors",
            host_device_descriptors(root, &seed_hash),
        ),
        ("sensors", host_sensors(root)),
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
    let unread: Vec<Value> = ["smbios", "acpi", "pci", "device_descriptors", "sensors"]
        .into_iter()
        .filter(|key| {
            profile["analysis"][key]
                .as_object()
                .is_some_and(serde_json::Map::is_empty)
        })
        .map(|key| Value::String(key.into()))
        .collect();
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
        dsdt[16..24].copy_from_slice(b"TP-N32  ");
        dsdt[24..28].copy_from_slice(&1u32.to_le_bytes());
        dsdt[28..32].copy_from_slice(b"ACPI");
        std::fs::write(tables.join("DSDT"), &dsdt).unwrap();
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
        assert_eq!(analysis["pci"]["subsystem_vendor_id"], 0x17aa);
        assert_eq!(profile["vcpu"], 2);
        // The host's serial and UUID must not reach the profile in any form.
        let text = serde_json::to_string(&profile).unwrap();
        assert!(!text.contains("PF2ABCDE"));
        assert!(!text.contains("3f2504e0"));

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
}
