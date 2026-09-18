//! Synthetic 24-port Broadcom-dialect `PoE` management MCU.
//! No powered devices are attached; enabling a port never invents power draw.

#[derive(Clone, Copy, Debug, Default)]
struct Port {
    enabled: u8,
    auto: u8,
    detection_type: u8,
    high_power_mode: u8,
    limit_type: u8,
    limit: u8,
    priority: u8,
    mapping: [u8; 7],
}

/// One system power bank, in big-endian deciwatts as the controller carries
/// them. Stock `hpcBrcmPoeSystemUsageThreshold` logs the pair as
/// `set max_power %d guard_band %d`.
#[derive(Clone, Copy, Debug, Default)]
struct PowerBank {
    max_power: u16,
    guard_band: u16,
}

/// The controller exposes eight banks; the vendor configures bank 7 and
/// leaves the rest zero.
const POWER_BANKS: usize = 8;

/// Budget reported before the guest has configured any bank. The
/// USW-Pro-24-PoE has a 400 W budget, and the vendor's own bank 7 —
/// 404.0 W less a 4.0 W guard band — resolves to the same number.
const DEFAULT_AVAILABLE_DECIWATTS: u16 = 4000;

#[derive(Debug, Default)]
pub(super) struct Poe {
    ports: [Port; 24],
    saved_ports: [Port; 24],
    power_mode: u8,
    power_config: u8,
    power_behaviour: [u8; 3],
    power_banks: [PowerBank; POWER_BANKS],
    config_mode: u8,
}

pub(super) fn checksum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0_u8, |sum, byte| sum.wrapping_add(*byte))
}

impl Poe {
    pub(super) fn request(&mut self, request: [u8; 12]) -> Option<[u8; 12]> {
        let mut reply = [0_u8; 12];
        reply[..2].copy_from_slice(&request[..2]);
        if checksum(&request[..11]) == request[11] {
            let port = usize::from(request[2]);
            match request[0] {
                0x20 => {
                    // Firmware fields decoded by stock switchdrvr 0x7a992c.
                    // Version 3.0.0.2 is the image's expected MCU firmware.
                    reply[2..11].copy_from_slice(&[0, 24, 0, 0xe1, 0x21, 0x30, 0, 4, 2]);
                }
                0x02 if request[2] <= 3 => self.config_mode = request[2],
                0x06 if request[2] <= 1 => {
                    for entry in &mut self.ports {
                        entry.enabled = request[2];
                    }
                }
                0x09 if request[2] == 1 => self.ports = self.saved_ports,
                0xe0 if request[1] == 0xe0 => self.saved_ports = self.ports,
                0x17 if request[2] <= 4 => self.power_mode = request[2],
                // Stock 0x7a9180 expects status zero in reply byte 2.
                0x0d => self.power_config = request[2],
                // Stock 0x7a95b0: preallocation, startup strategy, overload.
                0x0b => self.power_behaviour.copy_from_slice(&request[2..5]),
                0x2b => {
                    // Stock 0x7b076c labels bytes 2..9: UVLO, disable
                    // preallocation, startup strategy, overload disconnect,
                    // double detection, OVLO, slave count, 60W load split.
                    // Synthetic defaults; three eight-port PSE slaves.
                    reply[8] = 3;
                    reply[3..6].copy_from_slice(&self.power_behaviour);
                }
                0x2c if request[2] == 1 => {
                    // Stock 0x7a6384 reads config, mode, then six bank bytes.
                    reply[2] = self.power_config;
                    reply[3] = self.power_mode;
                }
                0x18 if port < POWER_BANKS => {
                    // Stock 0x7a6554 sets one power bank: byte 2 the bank
                    // index, bytes 3..5 the maximum power and bytes 5..7 the
                    // guard band, both big-endian. Its caller at 0x7a6a70
                    // names them `max_power` and `guard_band`. The reply
                    // carries a status in byte 3, which stays zero here.
                    //
                    // The vendor writes banks 0..6 as zero and bank 7 as
                    // 4040/40, which is 404.0 W less a 4.0 W guard band.
                    self.power_banks[port] = PowerBank {
                        max_power: u16::from_be_bytes([request[3], request[4]]),
                        guard_band: u16::from_be_bytes([request[5], request[6]]),
                    };
                }
                0x23 => {
                    // Stock 0x7a2d34 decodes allocated and available power as
                    // big-endian deciwatts. Nothing is drawing power, and the
                    // budget is whatever the guest configured its banks to.
                    reply[2..4].copy_from_slice(&0_u16.to_be_bytes());
                    reply[4..6].copy_from_slice(&self.available_deciwatts().to_be_bytes());
                }
                0x0e if port < 24 => self.ports[port].mapping.copy_from_slice(&request[3..10]),
                0x10 | 0x11 | 0x13 => {
                    // Stock switchdrvr sub_7a2588 (opcode 0x10),
                    // sub_7a8c78 (opcode 0x11), and sub_7a5e18 (opcode 0x13)
                    // encode up to two
                    // port/detection-type pairs in bytes 2..5. A 0xff port
                    // marks an unused pair. The two controller dialects
                    // accept public detection-mode values 0..6, 0..1, and
                    // 0..3, respectively.
                    let max_detection_type = match request[0] {
                        0x10 => 6,
                        0x11 => 1,
                        _ => 3,
                    };
                    for pair in request[2..6].chunks_exact(2) {
                        if pair[0] != 0xff && (pair[0] >= 24 || pair[1] > max_detection_type) {
                            return None;
                        }
                    }
                    for (pair, output) in request[2..6]
                        .chunks_exact(2)
                        .zip(reply[2..6].chunks_exact_mut(2))
                    {
                        output[0] = pair[0];
                        if pair[0] != 0xff {
                            self.ports[usize::from(pair[0])].detection_type = pair[1];
                        }
                    }
                }
                0x1c if port < 24 && request[3] <= 7 => {
                    // Stock switchdrvr sub_7a4b0c calls this High Power Mode
                    // (also Power Up Mode). Its reply is a single status in
                    // byte 2, which remains zero on success.
                    self.ports[port].high_power_mode = request[3];
                }
                0x00 | 0x15 | 0x16 | 0x1a if port < 24 => {
                    let entry = &mut self.ports[port];
                    match request[0] {
                        0x00 if request[3] <= 1 => entry.enabled = request[3],
                        0x15 => entry.limit_type = request[3],
                        0x16 => entry.limit = request[3],
                        0x1a if request[3] <= 3 => entry.priority = request[3],
                        _ => return None,
                    }
                    reply[2] = request[2];
                }
                0x12 => {
                    // Two port/value pairs; 0xff denotes an unused pair.
                    for pair in request[2..6].chunks_exact(2) {
                        if pair[0] != 0xff && (pair[0] >= 24 || pair[1] > 1) {
                            return None;
                        }
                    }
                    for (pair, output) in request[2..6]
                        .chunks_exact(2)
                        .zip(reply[2..6].chunks_exact_mut(2))
                    {
                        output[0] = pair[0];
                        if pair[0] != 0xff {
                            self.ports[usize::from(pair[0])].auto = pair[1];
                        }
                    }
                }
                0x21 | 0x25 | 0x26 | 0x30 if port < 24 => {
                    let entry = self.ports[port];
                    reply[2] = request[2];
                    match request[0] {
                        0x21 => reply[3] = entry.enabled, // disabled or searching, never delivering
                        0x25 => reply[4] = entry.auto,
                        0x26 => {
                            reply[4] = entry.limit_type;
                            reply[5] = entry.limit;
                            reply[6] = entry.priority;
                            let m = entry.mapping;
                            reply[7] = (m[0] << 7) | (m[1] << 3) | (m[2] & 7);
                            reply[8] = (m[3] & 7) | (m[4] << 3) | (m[5] << 5) | (m[6] << 7);
                        }
                        // 1.25 * (220 - raw) C: synthetic ambient 25 C.
                        // No attached PD: zero measured voltage/current/power.
                        0x30 => reply[8] = 200,
                        _ => return None,
                    }
                }
                _ => return None,
            }
        } else {
            reply[0] = 0xfe;
        }
        reply[11] = checksum(&reply[..11]);
        Some(reply)
    }

    /// Budget the controller reports as available. The banks the guest
    /// configures are the authority; the largest one wins, since the vendor
    /// leaves every bank but the one it uses at zero.
    fn available_deciwatts(&self) -> u16 {
        self.power_banks
            .iter()
            .map(|bank| bank.max_power.saturating_sub(bank.guard_band))
            .max()
            .filter(|budget| *budget != 0)
            .unwrap_or(DEFAULT_AVAILABLE_DECIWATTS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(op: u8, port: u8, value: u8) -> [u8; 12] {
        let mut request = [0xff; 12];
        request[..4].copy_from_slice(&[op, 0xff, port, value]);
        request[11] = checksum(&request[..11]);
        request
    }

    #[test]
    fn captured_system_info_request_returns_valid_identity() {
        let mut poe = Poe::default();
        let reply = poe.request(frame(0x20, 0xff, 0xff)).unwrap();
        assert_eq!(
            &reply[..11],
            &[0x20, 0xff, 0, 24, 0, 0xe1, 0x21, 0x30, 0, 4, 2]
        );
        assert_eq!(reply[11], checksum(&reply[..11]));
    }

    #[test]
    fn captured_power_bank_frames_are_accepted_and_set_the_budget() {
        let mut poe = Poe::default();
        // The eight frames the vendor sends at PoE init, byte for byte, as
        // the model's own SMBus log recorded them. Banks 0..6 are cleared and
        // bank 7 carries 404.0 W with a 4.0 W guard band.
        for bank in 0..7 {
            let mut request = [0xff_u8; 12];
            request[..7].copy_from_slice(&[0x18, 0xff, bank, 0, 0, 0, 0]);
            request[11] = checksum(&request[..11]);
            let reply = poe.request(request).expect("bank clear must be accepted");
            assert_eq!(reply[3], 0, "status byte must report success");
            assert_eq!(reply[11], checksum(&reply[..11]));
        }
        let mut request = [0xff_u8; 12];
        request[..7].copy_from_slice(&[0x18, 0xff, 7, 0x0f, 0xc8, 0x00, 0x28]);
        request[11] = checksum(&request[..11]);
        assert_eq!(request[11], 0x19, "checksum must match the captured frame");
        assert!(poe.request(request).is_some());
        assert_eq!(poe.power_banks[7].max_power, 4040);
        assert_eq!(poe.power_banks[7].guard_band, 40);

        // The configured bank is what the allocation query then reports.
        let reply = poe.request(frame(0x23, 0xff, 0xff)).unwrap();
        assert_eq!(
            u16::from_be_bytes([reply[2], reply[3]]),
            0,
            "nothing drawing"
        );
        assert_eq!(u16::from_be_bytes([reply[4], reply[5]]), 4000);
    }

    #[test]
    fn unconfigured_banks_report_the_board_budget() {
        let mut poe = Poe::default();
        let reply = poe.request(frame(0x23, 0xff, 0xff)).unwrap();
        assert_eq!(u16::from_be_bytes([reply[4], reply[5]]), 4000);
    }

    #[test]
    fn a_bank_index_past_the_controller_is_rejected() {
        assert!(
            Poe::default()
                .request(frame(0x18, POWER_BANKS as u8, 0))
                .is_none()
        );
    }

    #[test]
    fn bad_checksum_reports_protocol_error_without_mutation() {
        let mut poe = Poe::default();
        let mut request = frame(0, 0, 1);
        request[11] ^= 1;
        assert_eq!(poe.request(request).unwrap()[0], 0xfe);
        assert_eq!(poe.ports[0].enabled, 0);
    }

    #[test]
    fn enabled_port_searches_without_inventing_a_powered_device() {
        let mut poe = Poe::default();
        poe.request(frame(0, 2, 1)).unwrap();
        assert_eq!(poe.request(frame(0x21, 2, 0xff)).unwrap()[3], 1);
        assert_eq!(
            &poe.request(frame(0x30, 2, 0xff)).unwrap()[3..11],
            &[0, 0, 0, 0, 0, 200, 0, 0]
        );
    }

    #[test]
    fn unsupported_command_and_invalid_port_do_not_ack() {
        let mut poe = Poe::default();
        assert_eq!(poe.request(frame(0x7f, 0, 0)), None);
        assert_eq!(poe.request(frame(0, 24, 1)), None);
    }

    #[test]
    fn limits_and_priority_round_trip_in_extended_configuration() {
        let mut poe = Poe::default();
        poe.request(frame(0x15, 3, 2)).unwrap();
        poe.request(frame(0x16, 3, 150)).unwrap();
        poe.request(frame(0x1a, 3, 1)).unwrap();
        let reply = poe.request(frame(0x26, 3, 0xff)).unwrap();
        assert_eq!(&reply[4..7], &[2, 150, 1]);
    }

    #[test]
    fn save_and_soft_reset_restore_settings_but_new_device_is_fresh() {
        let mut poe = Poe::default();
        poe.request(frame(0, 4, 1)).unwrap();
        let mut save = frame(0xe0, 0xff, 0xff);
        save[1] = 0xe0;
        save[11] = checksum(&save[..11]);
        poe.request(save).unwrap();
        poe.request(frame(0, 4, 0)).unwrap();
        poe.request(frame(9, 1, 0xff)).unwrap();
        assert_eq!(poe.ports[4].enabled, 1);
        assert_eq!(Poe::default().ports[4].enabled, 0);
    }

    #[test]
    fn paired_auto_update_is_atomic_when_second_port_is_invalid() {
        let mut poe = Poe::default();
        let mut request = frame(0x12, 3, 1);
        request[4] = 24;
        request[5] = 1;
        request[11] = checksum(&request[..11]);
        assert_eq!(poe.request(request), None);
        assert_eq!(poe.ports[3].auto, 0);
    }

    #[test]
    fn automatic_mode_uses_the_second_configuration_field() {
        let mut poe = Poe::default();
        poe.request(frame(0x12, 3, 1)).unwrap();
        let reply = poe.request(frame(0x25, 3, 0xff)).unwrap();
        assert_eq!(&reply[2..5], &[3, 0, 1]);
    }

    #[test]
    fn detection_type_supports_single_and_paired_port_updates() {
        let mut poe = Poe::default();
        assert_eq!(poe.request(frame(0x10, 8, 4)).unwrap()[2..4], [8, 0]);
        assert_eq!(poe.ports[8].detection_type, 4);

        let mut paired = frame(0x10, 16, 2);
        paired[4..6].copy_from_slice(&[17, 2]);
        paired[11] = checksum(&paired[..11]);
        assert_eq!(poe.request(paired).unwrap()[2..6], [16, 0, 17, 0]);
        assert_eq!(poe.ports[16].detection_type, 2);
        assert_eq!(poe.ports[17].detection_type, 2);
    }

    #[test]
    fn detection_type_pair_is_atomic_when_one_field_is_invalid() {
        let mut poe = Poe::default();
        let mut request = frame(0x10, 3, 4);
        request[4..6].copy_from_slice(&[24, 2]);
        request[11] = checksum(&request[..11]);
        assert_eq!(poe.request(request), None);
        assert_eq!(poe.ports[3].detection_type, 0);
    }

    #[test]
    fn alternate_detection_type_dialect_matches_captured_startup_request() {
        let mut poe = Poe::default();
        let request = [
            0x13, 0xff, 0x0d, 2, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1a,
        ];
        let reply = poe.request(request).unwrap();
        assert_eq!(&reply[2..6], &[0x0d, 0, 0xff, 0]);
        assert_eq!(poe.ports[0x0d].detection_type, 2);
        assert_eq!(reply[11], checksum(&reply[..11]));

        assert_eq!(poe.request(frame(0x13, 0, 4)), None);
        assert_eq!(poe.ports[0].detection_type, 0);
    }

    #[test]
    fn opcode_11_detection_type_matches_captured_startup_request() {
        let mut poe = Poe::default();
        let request = [
            0x11, 0xff, 0x15, 1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1f,
        ];
        let reply = poe.request(request).unwrap();
        assert_eq!(&reply[2..6], &[0x15, 0, 0xff, 0]);
        assert_eq!(poe.ports[0x15].detection_type, 1);
        assert_eq!(reply[11], checksum(&reply[..11]));

        assert_eq!(poe.request(frame(0x11, 0, 2)), None);
        assert_eq!(poe.ports[0].detection_type, 0);
    }

    #[test]
    fn high_power_mode_matches_captured_startup_request() {
        let mut poe = Poe::default();
        let request = [
            0x1c, 0xff, 0x15, 5, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x2e,
        ];
        let reply = poe.request(request).unwrap();
        assert_eq!(reply[2], 0);
        assert_eq!(poe.ports[0x15].high_power_mode, 5);
        assert_eq!(reply[11], checksum(&reply[..11]));

        assert_eq!(poe.request(frame(0x1c, 0, 8)), None);
        assert_eq!(poe.ports[0].high_power_mode, 0);
        assert_eq!(poe.request(frame(0x1c, 24, 5)), None);
    }

    #[test]
    fn captured_power_configuration_round_trips() {
        let mut poe = Poe::default();
        let request = [
            0x0d, 0xff, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x23,
        ];
        assert_eq!(poe.request(request).unwrap()[2], 0);
        poe.request(frame(0x17, 2, 0xff)).unwrap();
        let reply = poe.request(frame(0x2c, 1, 0xff)).unwrap();
        assert_eq!(&reply[2..4], &[0x1f, 2]);
        assert_eq!(reply[11], checksum(&reply[..11]));
        assert_eq!(Poe::default().power_config, 0);
    }

    #[test]
    fn captured_extended_configuration_reports_three_slaves() {
        let request = [
            0x2b, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x22,
        ];
        let reply = Poe::default().request(request).unwrap();
        assert_eq!(&reply[..10], &[0x2b, 0, 0, 0, 0, 0, 0, 0, 3, 0]);
        assert_eq!(reply[11], checksum(&reply[..11]));
    }

    #[test]
    fn captured_power_behaviour_updates_extended_configuration() {
        let mut poe = Poe::default();
        let request = [0x0b, 0, 1, 1, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 7];
        assert_eq!(poe.request(request).unwrap()[2], 0);
        let reply = poe.request(frame(0x2b, 0xff, 0xff)).unwrap();
        assert_eq!(&reply[3..6], &[1, 1, 0]);
        assert_eq!(reply[8], 3);
    }

    #[test]
    fn system_power_status_reports_an_idle_400_watt_budget() {
        let reply = Poe::default().request(frame(0x23, 0xff, 0xff)).unwrap();
        assert_eq!(&reply[2..8], &[0, 0, 0x0f, 0xa0, 0, 0]);
    }
}
