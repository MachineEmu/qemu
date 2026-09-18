//! Command-line utilities for inspecting board models.

use board_core::{AddressMap, Window};
use board_tools::{generate_eeprom, generate_emmc, replay_recording, validate_recording};

fn windows(board: &str) -> Result<AddressMap, String> {
    let values = match board {
        "mt7981" => vec![
            Window {
                base: 0x0800_0000,
                size: 0x1000,
                priority: 0,
                device: 0,
            },
            Window {
                base: 0x1000_0000,
                size: 0x0200_0000,
                priority: 0,
                device: 4,
            },
            Window {
                base: 0x1800_0000,
                size: 0x0080_0000,
                priority: 0,
                device: 5,
            },
            Window {
                base: mt7981_machine::UART0_BASE,
                size: mt7981_machine::DEVICE_WINDOW_SIZE,
                priority: 1,
                device: 1,
            },
            Window {
                base: mt7981_machine::MSDC0_BASE,
                size: mt7981_machine::DEVICE_WINDOW_SIZE,
                priority: 1,
                device: 2,
            },
            Window {
                base: mt7981_machine::ETH_MAC_BASE,
                size: mt7981_machine::ETH_MAC_WINDOW_SIZE,
                priority: 0,
                device: 3,
            },
        ],
        "udm-pro" => vec![
            Window {
                base: udmpro_machine::PCIE_CTRL_BASE,
                size: 0x20_000,
                priority: 0,
                device: 3,
            },
            Window {
                base: udmpro_machine::SPI_BASE,
                size: 0x1000,
                priority: 0,
                device: 4,
            },
            Window {
                base: udmpro_machine::SERDES_BASE,
                size: 0x2400,
                priority: 0,
                device: 5,
            },
            Window {
                base: udmpro_machine::INTERNAL_ECAM_BASE,
                size: 0x100_000,
                priority: 0,
                device: 6,
            },
            Window {
                base: udmpro_machine::UART_BASE,
                size: 0x1000,
                priority: 0,
                device: 1,
            },
            Window {
                base: udmpro_machine::PBS_BASE,
                size: 0x1000,
                priority: 0,
                device: 2,
            },
        ],
        _ => return Err(format!("unknown board: {board}")),
    };
    AddressMap::new(values).map_err(|error| error.to_string())
}

fn main() {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_default();
    match command.as_str() {
        "mmio-map" => match windows(&args.next().unwrap_or_default()) {
            Ok(map) => {
                for window in map.windows() {
                    println!(
                        "0x{:016x} 0x{:x} {} {}",
                        window.base, window.size, window.priority, window.device
                    );
                }
            }
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(2);
            }
        },
        "trace-summary" => {
            let path = args.next().unwrap_or_default();
            let text = std::fs::read_to_string(path).unwrap_or_else(|error| {
                eprintln!("{error}");
                std::process::exit(2);
            });
            let board = args.next().unwrap_or_else(|| "mt7981".into());
            let map = windows(&board).unwrap_or_else(|error| {
                eprintln!("{error}");
                std::process::exit(2);
            });
            let mut records = 0;
            let mut unknown = 0;
            let mut per_window = std::collections::BTreeMap::<u32, usize>::new();
            for line in text.lines() {
                records += 1;
                let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };
                if value.get("type").and_then(serde_json::Value::as_str) != Some("input") {
                    continue;
                }
                let Some(address) = value.get("address").and_then(serde_json::Value::as_u64) else {
                    continue;
                };
                if let Some(window) = map.lookup(address) {
                    *per_window.entry(window.device).or_default() += 1;
                } else {
                    unknown += 1;
                }
            }
            println!("records={records} unknown={unknown}");
            for (device, count) in per_window {
                println!("window={device} inputs={count}");
            }
        }
        "validate" => {
            let path = std::path::PathBuf::from(args.next().unwrap_or_default());
            let blobs = std::path::PathBuf::from(args.next().unwrap_or_else(|| ".".into()));
            match validate_recording(&path, &blobs) {
                Ok(count) => println!("valid inputs={count}"),
                Err(error) => {
                    eprintln!("{error}");
                    std::process::exit(1);
                }
            }
        }
        "replay" => {
            let path = std::path::PathBuf::from(args.next().unwrap_or_default());
            let blobs = std::path::PathBuf::from(args.next().unwrap_or_else(|| ".".into()));
            match replay_recording(&path, &blobs) {
                Ok(count) => println!("replay ok inputs={count}"),
                Err(error) => {
                    eprintln!("{error}");
                    std::process::exit(1);
                }
            }
        }
        "eeprom-gen" | "emmc-gen" => {
            let output = args.next().unwrap_or_else(|| "image.bin".to_owned());
            let image = if command == "eeprom-gen" {
                generate_eeprom()
            } else {
                generate_emmc()
            };
            std::fs::write(output, image).unwrap_or_else(|error| {
                eprintln!("{error}");
                std::process::exit(2);
            });
        }
        _ => {
            eprintln!(
                "usage: board-tools mmio-map <mt7981|udm-pro> | trace-summary <trace.jsonl> [board] | replay <trace.jsonl> [blob-dir] | validate <trace.jsonl> [blob-dir]"
            );
            std::process::exit(2);
        }
    }
}
