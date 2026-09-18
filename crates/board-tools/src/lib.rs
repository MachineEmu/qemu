//! Replay recording schema and validation.

use board_core::dma::{DmaBus, TransferStatus};
use board_core::{AccessWidth, Machine, MachineContext, MmioError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Current JSONL recording schema version.
pub const RECORDING_VERSION: u32 = 1;

/// Builds the deterministic U6+ EEPROM image used by the board model.
pub fn generate_eeprom() -> Vec<u8> {
    mt7981_machine::generate_eeprom()
}

/// Builds the minimal high-capacity card backing image used by the legacy adapter.
pub fn generate_emmc() -> Vec<u8> {
    let mut image = vec![0; 8 * 1024 * 1024];
    image[192] = 8;
    image[194] = 2;
    image[214] = 0x80;
    image[215] = 0;
    image
}

/// A blob referenced by a recording header.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlobRef {
    /// File name relative to the recording blob directory.
    pub name: String,
    /// Expected SHA-256 digest in lowercase hexadecimal.
    pub sha256: String,
    /// Image kind passed to the board ABI (`1` EEPROM, `2` eMMC).
    #[serde(default)]
    pub kind: u32,
}

/// The first line of every recording.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecordingHeader {
    /// Discriminator for schema validation.
    #[serde(rename = "type")]
    pub record_type: String,
    /// Schema version.
    pub version: u32,
    /// Board model name.
    pub board: String,
    /// Image files needed to replay the recording.
    #[serde(default)]
    pub blobs: Vec<BlobRef>,
}

/// One ordered input or capture error.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecordingInput {
    /// Discriminator for schema validation.
    #[serde(rename = "type")]
    pub record_type: String,
    /// Monotonic input sequence number.
    pub sequence: u64,
    /// Virtual timestamp in nanoseconds.
    pub now_ns: u64,
    /// Input kind, for example `mmio_read` or `net_rx`.
    pub kind: String,
    /// Set by a recorder when any transaction was lost.
    #[serde(default)]
    pub capture_error: bool,
    /// MMIO address for an MMIO input.
    #[serde(default)]
    pub address: Option<u64>,
    /// MMIO access width in bytes.
    #[serde(default)]
    pub width: Option<u8>,
    /// MMIO write value.
    #[serde(default)]
    pub value: Option<u64>,
    /// Incoming UART or network payload, when applicable.
    #[serde(default)]
    pub data: Option<Vec<u8>>,
    /// Optional expected read value from the reference recording.
    #[serde(default)]
    pub expected_value: Option<u64>,
    /// Optional expected status (`ok`, `unmapped`, `invalid`, or `bus_error`).
    #[serde(default)]
    pub expected_status: Option<String>,
    /// Ordered events emitted by the input.
    #[serde(default)]
    pub events: Vec<RecordedEvent>,
}

/// One event emitted by a captured execution call.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecordedEvent {
    /// ABI event kind.
    pub kind: u32,
    /// IRQ line or UART port.
    pub line_or_port: u32,
    /// Event level or byte value.
    pub value: u64,
    /// Optional event payload, such as a transmitted frame.
    #[serde(default)]
    pub data: Vec<u8>,
}

/// One expected DMA transaction in a replay fixture.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DmaRecord {
    /// Discriminator for schema validation.
    #[serde(rename = "type")]
    pub record_type: String,
    /// `read` or `write`.
    pub operation: String,
    /// Guest physical address.
    pub address: u64,
    /// Bytes returned by a read or expected for a write.
    pub data: Vec<u8>,
    /// Whether the reference transfer succeeded.
    pub status: bool,
}

/// Strict DMA bus for deterministic engine replay.
#[derive(Debug)]
pub struct ReplayDmaBus {
    records: Vec<DmaRecord>,
    cursor: usize,
    failed: bool,
}

impl ReplayDmaBus {
    /// Creates a replay bus from its ordered transaction fixture.
    pub fn new(records: Vec<DmaRecord>) -> Self {
        Self {
            records,
            cursor: 0,
            failed: false,
        }
    }
    /// Returns whether every fixture transaction was consumed without mismatch.
    pub fn finish(&self) -> Result<(), &'static str> {
        if self.failed {
            Err("DMA transaction mismatch")
        } else if self.cursor != self.records.len() {
            Err("DMA transactions remain unconsumed")
        } else {
            Ok(())
        }
    }
    fn next(&mut self, operation: &str, address: u64, data: &[u8]) -> Option<DmaRecord> {
        let record = self.records.get(self.cursor)?.clone();
        self.cursor += 1;
        if record.operation != operation
            || record.address != address
            || record.data.len() != data.len()
        {
            self.failed = true;
            return None;
        }
        if operation == "write" && record.data != data {
            self.failed = true;
            return None;
        }
        Some(record)
    }
}

impl DmaBus for ReplayDmaBus {
    fn read(&mut self, address: u64, buffer: &mut [u8]) -> TransferStatus {
        let Some(record) = self.next("read", address, buffer) else {
            return TransferStatus::Failed;
        };
        if !record.status {
            return TransferStatus::Failed;
        }
        buffer.copy_from_slice(&record.data);
        TransferStatus::Complete
    }
    fn write(&mut self, address: u64, buffer: &[u8]) -> TransferStatus {
        self.next("write", address, buffer)
            .map_or(TransferStatus::Failed, |record| {
                if record.status {
                    TransferStatus::Complete
                } else {
                    TransferStatus::Failed
                }
            })
    }
}

/// Validation failure.
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    /// File I/O failed.
    #[error("recording I/O: {0}")]
    Io(#[from] std::io::Error),
    /// A JSONL line did not match the schema.
    #[error("recording line {line}: {error}")]
    Json { line: usize, error: String },
    /// A recording invariant was violated.
    #[error("recording line {line}: {message}")]
    Invalid { line: usize, message: String },
}

/// Validates schema, sequence continuity, capture completeness, and blobs.
pub fn validate_recording(path: &Path, blob_dir: &Path) -> Result<usize, ValidationError> {
    let contents = std::fs::read_to_string(path)?;
    let mut lines = contents.lines();
    let header_line = lines.next().ok_or_else(|| ValidationError::Invalid {
        line: 1,
        message: "missing header".into(),
    })?;
    let header: RecordingHeader =
        serde_json::from_str(header_line).map_err(|error| ValidationError::Json {
            line: 1,
            error: error.to_string(),
        })?;
    if header.record_type != "header"
        || header.version != RECORDING_VERSION
        || header.board.is_empty()
    {
        return Err(ValidationError::Invalid {
            line: 1,
            message: "invalid header".into(),
        });
    }
    for blob in &header.blobs {
        let bytes = std::fs::read(blob_dir.join(&blob.name))?;
        let digest = hex::encode(Sha256::digest(bytes));
        if digest != blob.sha256 {
            return Err(ValidationError::Invalid {
                line: 1,
                message: format!(
                    "blob {} has digest {digest}, expected {}",
                    blob.name, blob.sha256
                ),
            });
        }
    }
    let mut expected_sequence = 0;
    let mut inputs = 0;
    for (offset, line) in lines.enumerate() {
        let line_number = offset + 2;
        let value: serde_json::Value =
            serde_json::from_str(line).map_err(|error| ValidationError::Json {
                line: line_number,
                error: error.to_string(),
            })?;
        let record_type = value
            .get("type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if record_type == "dma" {
            let dma: DmaRecord =
                serde_json::from_value(value).map_err(|error| ValidationError::Json {
                    line: line_number,
                    error: error.to_string(),
                })?;
            if dma.record_type != "dma" || (dma.operation != "read" && dma.operation != "write") {
                return Err(ValidationError::Invalid {
                    line: line_number,
                    message: "invalid DMA record".into(),
                });
            }
            continue;
        }
        let input: RecordingInput =
            serde_json::from_value(value).map_err(|error| ValidationError::Json {
                line: line_number,
                error: error.to_string(),
            })?;
        if input.record_type != "input" || input.sequence != expected_sequence {
            return Err(ValidationError::Invalid {
                line: line_number,
                message: format!("expected input sequence {expected_sequence}"),
            });
        }
        if input.capture_error {
            return Err(ValidationError::Invalid {
                line: line_number,
                message: "capture contains an error".into(),
            });
        }
        expected_sequence =
            expected_sequence
                .checked_add(1)
                .ok_or_else(|| ValidationError::Invalid {
                    line: line_number,
                    message: "sequence overflow".into(),
                })?;
        inputs += 1;
    }
    Ok(inputs)
}

/// Failure while executing a validated recording against a Rust board model.
#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    /// The recording could not be validated first.
    #[error("replay validation: {0}")]
    Validation(#[from] ValidationError),
    /// The recording contained an unsupported or malformed input.
    #[error("replay line {line}: {message}")]
    Input { line: usize, message: String },
    /// The model result differed from the reference result.
    #[error("replay line {line}: {message}")]
    Divergence { line: usize, message: String },
    /// The recording's DMA stream was not consumed exactly.
    #[error("replay DMA: {0}")]
    Dma(&'static str),
    /// File I/O failed while reading the recording.
    #[error("replay I/O: {0}")]
    Io(#[from] std::io::Error),
}

fn expected_status(result: &Result<u64, MmioError>) -> String {
    match result {
        Ok(_) => "ok".into(),
        Err(MmioError::Unmapped) => "unmapped".into(),
        Err(MmioError::InvalidWidth | MmioError::Misaligned) => "invalid".into(),
        Err(MmioError::BusError) => "bus_error".into(),
    }
}

fn replay_input<M: Machine>(
    machine: &mut M,
    dma: &mut ReplayDmaBus,
    input: &RecordingInput,
    line: usize,
) -> Result<(), ReplayError> {
    let mut ctx = MachineContext::with_dma(input.now_ns, dma);
    machine.advance_to(&mut ctx);
    let result = match input.kind.as_str() {
        "reset" => {
            machine.reset(&mut ctx);
            Ok(0)
        }
        "advance" | "timer" => Ok(u64::from(machine.take_uart_tx().unwrap_or(0))),
        "uart_rx" => {
            let byte = input.value.ok_or_else(|| ReplayError::Input {
                line,
                message: "UART input is missing byte value".into(),
            })?;
            if byte > u64::from(u8::MAX) {
                return Err(ReplayError::Input {
                    line,
                    message: "UART input byte is out of range".into(),
                });
            }
            machine.uart_rx(&mut ctx, input.address.unwrap_or(0) as u32, byte as u8);
            Ok(0)
        }
        "net_rx" => {
            let frame = input.data.as_deref().ok_or_else(|| ReplayError::Input {
                line,
                message: "network input is missing frame data".into(),
            })?;
            machine.net_rx(&mut ctx, input.address.unwrap_or(0) as u32, frame);
            Ok(0)
        }
        "mmio_read" | "mmio_write" => {
            let address = input.address.ok_or_else(|| ReplayError::Input {
                line,
                message: "MMIO input is missing address".into(),
            })?;
            let width = AccessWidth::from_bytes(input.width.ok_or_else(|| ReplayError::Input {
                line,
                message: "MMIO input is missing width".into(),
            })?)
            .ok_or_else(|| ReplayError::Input {
                line,
                message: "MMIO input has unsupported width".into(),
            })?;
            if input.kind == "mmio_read" {
                machine.mmio_read(&mut ctx, address, width)
            } else {
                machine
                    .mmio_write(&mut ctx, address, input.value.unwrap_or(0), width)
                    .map(|()| 0)
            }
        }
        other => {
            return Err(ReplayError::Input {
                line,
                message: format!("unsupported input kind {other}"),
            });
        }
    };
    let actual_status = expected_status(&result);
    if input
        .expected_status
        .as_deref()
        .is_some_and(|expected| expected != actual_status)
    {
        return Err(ReplayError::Divergence {
            line,
            message: format!(
                "status {actual_status}, expected {:?}",
                input.expected_status
            ),
        });
    }
    if let (Some(expected), Ok(actual)) = (input.expected_value, result)
        && actual != expected
    {
        return Err(ReplayError::Divergence {
            line,
            message: format!("value 0x{actual:x}, expected 0x{expected:x}"),
        });
    }
    let actual_events: Vec<RecordedEvent> = ctx
        .events
        .iter()
        .map(|event| match event {
            board_core::Event::IrqLevel { line, level } => RecordedEvent {
                kind: 1,
                line_or_port: *line,
                value: u64::from(*level),
                data: vec![],
            },
            board_core::Event::UartTx { port, byte } => RecordedEvent {
                kind: 2,
                line_or_port: *port,
                value: u64::from(*byte),
                data: vec![],
            },
            board_core::Event::NetTx { port, frame } => RecordedEvent {
                kind: 4,
                line_or_port: *port,
                value: u64::try_from(frame.len()).unwrap_or(u64::MAX),
                data: frame.clone(),
            },
            board_core::Event::NetTxOffload {
                port,
                queue,
                request,
                frame,
            } => {
                let mut data = request.encode().to_vec();
                data.extend_from_slice(frame);
                RecordedEvent {
                    kind: 5,
                    line_or_port: *port,
                    value: u64::from(*queue),
                    data,
                }
            }
            board_core::Event::FrontPanel { payload } => RecordedEvent {
                kind: 6,
                line_or_port: 0,
                value: 0,
                data: payload.clone(),
            },
            board_core::Event::ResetRequest => RecordedEvent {
                kind: 3,
                line_or_port: 0,
                value: 0,
                data: vec![],
            },
        })
        .collect();
    if actual_events != input.events {
        return Err(ReplayError::Divergence {
            line,
            message: format!("events {actual_events:?}, expected {:?}", input.events),
        });
    }
    Ok(())
}

/// Replays every ordered input and DMA transaction in a recording.
pub fn replay_recording(path: &Path, blob_dir: &Path) -> Result<usize, ReplayError> {
    validate_recording(path, blob_dir)?;
    let contents = std::fs::read_to_string(path)?;
    let mut lines = contents.lines();
    let header: RecordingHeader =
        serde_json::from_str(lines.next().ok_or_else(|| ReplayError::Input {
            line: 1,
            message: "missing header".into(),
        })?)
        .map_err(|error| ReplayError::Input {
            line: 1,
            message: error.to_string(),
        })?;
    let mut inputs = Vec::new();
    let mut dma_records = Vec::new();
    for (offset, line) in lines.enumerate() {
        let line_number = offset + 2;
        let value: serde_json::Value =
            serde_json::from_str(line).map_err(|error| ReplayError::Input {
                line: line_number,
                message: error.to_string(),
            })?;
        if value.get("type").and_then(serde_json::Value::as_str) == Some("dma") {
            dma_records.push(serde_json::from_value(value).map_err(|error| {
                ReplayError::Input {
                    line: line_number,
                    message: error.to_string(),
                }
            })?);
        } else {
            inputs.push((
                line_number,
                serde_json::from_value(value).map_err(|error| ReplayError::Input {
                    line: line_number,
                    message: error.to_string(),
                })?,
            ));
        }
    }
    let mut dma = ReplayDmaBus::new(dma_records);
    let count = match header.board.as_str() {
        "mt7981" => {
            let mut machine = mt7981_machine::Mt7981Board::new();
            for blob in &header.blobs {
                let bytes = std::fs::read(blob_dir.join(&blob.name))?;
                match blob.kind {
                    1 => machine
                        .load_eeprom_image(&bytes)
                        .map_err(|error| ReplayError::Input {
                            line: 1,
                            message: error.to_string(),
                        })?,
                    2 => machine
                        .load_emmc_image(&bytes)
                        .map_err(|error| ReplayError::Input {
                            line: 1,
                            message: error.to_string(),
                        })?,
                    0 => {}
                    kind => {
                        return Err(ReplayError::Input {
                            line: 1,
                            message: format!("unsupported blob kind {kind}"),
                        });
                    }
                }
            }
            for (line, input) in &inputs {
                replay_input(&mut machine, &mut dma, input, *line)?;
            }
            inputs.len()
        }
        "udm-pro" => {
            let mut machine = udmpro_machine::UdmProBoard::new();
            if header.blobs.iter().any(|blob| blob.kind != 0) {
                return Err(ReplayError::Input {
                    line: 1,
                    message: "UDM Pro image replay is not implemented".into(),
                });
            }
            for (line, input) in &inputs {
                replay_input(&mut machine, &mut dma, input, *line)?;
            }
            inputs.len()
        }
        other => {
            return Err(ReplayError::Input {
                line: 1,
                message: format!("unsupported board {other}"),
            });
        }
    };
    dma.finish().map_err(ReplayError::Dma)?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn validator_accepts_complete_contiguous_recording() {
        let root = std::env::temp_dir().join(format!(
            "board-recording-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let header = RecordingHeader {
            record_type: "header".into(),
            version: RECORDING_VERSION,
            board: "mt7981".into(),
            blobs: vec![],
        };
        let input = RecordingInput {
            record_type: "input".into(),
            sequence: 0,
            now_ns: 0,
            kind: "reset".into(),
            capture_error: false,
            address: None,
            width: None,
            value: None,
            expected_value: None,
            data: None,
            expected_status: None,
            events: vec![],
        };
        std::fs::write(
            root.join("trace.jsonl"),
            format!(
                "{}\n{}\n",
                serde_json::to_string(&header).unwrap(),
                serde_json::to_string(&input).unwrap()
            ),
        )
        .unwrap();
        assert_eq!(
            validate_recording(&root.join("trace.jsonl"), &root).unwrap(),
            1
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn generated_eeprom_has_legacy_header_and_crc() {
        let image = generate_eeprom();
        assert_eq!(&image[0x8000..0x8004], b"UBNT");
        // SBD fields are big-endian.
        assert_eq!(&image[0x800c..0x8010], &[0, 2, 0, 2]);
        assert_eq!(&image[0x8010..0x8012], &[7, 0x77]);
        // The big-endian length at 0x8008 sets the CRC range, so the marker
        // at 0x8070 is covered; both hardware dumps store 0x65.
        let length = u32::from_be_bytes(image[0x8008..0x800c].try_into().unwrap());
        assert_eq!(length, 0x65);
        assert_eq!(image[0x8070], 0x01);
        assert_eq!(
            u32::from_le_bytes(image[0x8004..0x8008].try_into().unwrap()),
            {
                let mut crc = 0;
                for byte in &image[0x800c..0x800c + length as usize] {
                    crc ^= u32::from(*byte);
                    for _ in 0..8 {
                        crc = (crc >> 1) ^ if crc & 1 != 0 { 0xedb8_8320 } else { 0 };
                    }
                }
                crc
            }
        );
    }

    #[test]
    fn replay_dma_rejects_changed_payload_and_unconsumed_records() {
        let mut bus = ReplayDmaBus::new(vec![DmaRecord {
            record_type: "dma".into(),
            operation: "write".into(),
            address: 4,
            data: vec![1, 2],
            status: true,
        }]);
        assert_eq!(bus.write(4, &[1, 3]), TransferStatus::Failed);
        assert!(bus.finish().is_err());
        let mut bus = ReplayDmaBus::new(vec![DmaRecord {
            record_type: "dma".into(),
            operation: "read".into(),
            address: 4,
            data: vec![1, 2],
            status: true,
        }]);
        let mut data = [0; 2];
        assert_eq!(bus.read(4, &mut data), TransferStatus::Complete);
        assert_eq!(data, [1, 2]);
        assert!(bus.finish().is_ok());
    }

    #[test]
    fn replay_executes_mmio_inputs_and_checks_reference_value() {
        let root = std::env::temp_dir().join(format!(
            "board-replay-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let header = RecordingHeader {
            record_type: "header".into(),
            version: RECORDING_VERSION,
            board: "mt7981".into(),
            blobs: vec![],
        };
        let input = RecordingInput {
            record_type: "input".into(),
            sequence: 0,
            now_ns: 0,
            kind: "mmio_read".into(),
            capture_error: false,
            address: Some(mt7981_machine::CHIP_ID),
            width: Some(4),
            value: None,
            expected_value: Some(0x7981),
            data: None,
            expected_status: Some("ok".into()),
            events: vec![],
        };
        std::fs::write(
            root.join("trace.jsonl"),
            format!(
                "{}\n{}\n",
                serde_json::to_string(&header).unwrap(),
                serde_json::to_string(&input).unwrap()
            ),
        )
        .unwrap();
        assert_eq!(
            replay_recording(&root.join("trace.jsonl"), &root).unwrap(),
            1
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
