//! Semantic `UniFi` display emulator, not a framebuffer or MCU instruction emulator.
//! Framing and startup queries come from stock lcmd (see docs/us24pro/lcm.md).

use serde_json::{Map, Value, json};
use std::collections::VecDeque;

/// Maximum accepted JSON line, excluding its newline.
pub const MAX_LINE: usize = 4096;
/// Maximum aggregated USB transfer accepted from a host controller.
pub const MAX_TRANSFER: usize = 65536;
const MAX_QUEUE: usize = 65536;
const MAX_STATE: usize = 32768;
/// Firmware identity of the emulated application profile, not executing MCU code.
pub const VERSION: &str = "v5.4.4-0-g9aa6f80";
/// Identity advertised for the bundled USW display firmware profile.
pub const HASH: &str = "2252795598443a52f164e322c061dbf6";
/// Console screens known to UDM-Pro ulcmd 5.1.19 (`Console::Console`, `docs/udm-pro/lcm.md`).
pub const UDM_PRO_SCREENS: [&str; 9] = [
    "menu.main",
    "menu.network",
    "menu.protect",
    "menu.access",
    "menu.talk",
    "menu.connect",
    "menu.settings",
    "menu.info",
    "network.throughput",
];

/// A bounded newline JSON endpoint with independently observable display state.
#[derive(Default)]
pub struct Lcm {
    udm_pro: bool,
    line: Vec<u8>,
    discard: bool,
    replies: VecDeque<u8>,
    snapshot: Vec<u8>,
    ui: Map<String, Value>,
    system: Map<String, Value>,
    sequence: u64,
}

impl Lcm {
    /// UDM-Pro GD application identity supplied with firmware 5.1.19.
    #[must_use]
    pub fn udm_pro() -> Self {
        Self {
            udm_pro: true,
            ..Self::default()
        }
    }
    /// Inject a semantic display action, not raw coordinates or arbitrary USB data.
    /// Returns false without mutation for invalid actions or a full reply queue.
    ///
    /// US24PRO accepts `{"screen":..}` and `{"port":..}` once the guest has sent
    /// `communication:true`, `state:"ready"` and a screen. UDM-Pro accepts its own
    /// menu screens, `{"screensaver":bool}` and `{"dismiss":"<warning>"}`; stock
    /// ulcmd never pushes a screen until it navigates, so the UDM-Pro profile does
    /// not require one and assumes the display's own `menu.main` (docs/udm-pro/lcm.md).
    pub fn input(&mut self, bytes: &[u8]) -> bool {
        if bytes.len() > 1024 || self.replies.len() > MAX_QUEUE - 1024 {
            return false;
        }
        let Ok(Value::Object(action)) = serde_json::from_slice(bytes) else {
            return false;
        };
        if action.len() != 1
            || self.ui.get("communication") != Some(&json!(true))
            || self.ui.get("state") != Some(&json!("ready"))
            || (!self.udm_pro && !self.ui.contains_key("screen"))
        {
            return false;
        }
        let Some(events) = (if self.udm_pro {
            self.udm_pro_events(&action)
        } else {
            self.us24pro_events(&action)
        }) else {
            return false;
        };
        for event in &events {
            self.replies.extend(event.to_string().bytes());
            self.replies.push_back(b'\n');
        }
        for event in &events {
            if let Some(port) = event.get("port.id") {
                self.ui.insert("port.id".into(), port.clone());
            }
            if let Some(screen) = event.get("screen.changed") {
                self.ui.insert("screen".into(), screen.clone());
            }
            if let Some(saver) = event.get("screensaver") {
                self.ui.insert("screensaver".into(), saver.clone());
            }
        }
        self.publish(&json!({"input":action}), &json!({"status":"queued"}));
        true
    }

    /// Stock US24PRO lcmd event parser: `port.id` precedes `screen.changed:"port"`.
    fn us24pro_events(&self, action: &Map<String, Value>) -> Option<Vec<Value>> {
        if let Some(port) = action.get("port").and_then(Value::as_u64) {
            if !(1..=26).contains(&port) {
                return None;
            }
            return Some(vec![
                json!({"port.id":port}),
                json!({"screen.changed":"port"}),
            ]);
        }
        let screen = action.get("screen").and_then(Value::as_str)?;
        matches!(
            screen,
            "menu.main"
                | "menu.ports.type"
                | "menu.ports.up"
                | "menu.ports.down"
                | "info.rj45"
                | "info.sfp"
                | "ip.address"
                | "power"
        )
        .then(|| vec![json!({"screen.changed":screen})])
    }

    /// Events ulcmd 5.1.19 parses from the display (`SerialPlatformBase::ParseLcm*`).
    /// `control` actions run poweroff/reboot on the guest and are never exposed;
    /// `port.id` has no UDM-Pro console screen, so it is rejected as well.
    fn udm_pro_events(&self, action: &Map<String, Value>) -> Option<Vec<Value>> {
        if let Some(screen) = action.get("screen").and_then(Value::as_str) {
            return UDM_PRO_SCREENS
                .contains(&screen)
                .then(|| vec![json!({"screen.changed":screen})]);
        }
        if let Some(saver) = action.get("screensaver").and_then(Value::as_bool) {
            return Some(vec![json!({"screensaver":saver})]);
        }
        let warning = action.get("dismiss").and_then(Value::as_str)?;
        let known = self
            .ui
            .get("warnings")
            .and_then(Value::as_object)
            .is_some_and(|warnings| warnings.contains_key(warning));
        known.then(|| vec![json!({"warning.dismiss":warning})])
    }
    /// Clear application and transport state on USB reset.
    pub fn reset(&mut self) {
        *self = Self {
            udm_pro: self.udm_pro,
            ..Self::default()
        };
        self.publish(&Value::Null, &json!({"status":"reset"}));
    }

    /// Accept one USB OUT transfer atomically, or retry under backpressure.
    /// xHCI aggregates multiple 64-byte wire packets into one transfer. Reserve
    /// enough reply space for every completed line before changing stream state.
    #[expect(
        clippy::naive_bytecount,
        reason = "the bounded USB transfer does not justify another dependency"
    )]
    pub fn feed(&mut self, bytes: &[u8]) -> bool {
        let reserve = bytes.iter().filter(|&&byte| byte == b'\n').count() * 256;
        if bytes.len() > MAX_TRANSFER || reserve > MAX_QUEUE - self.replies.len() {
            return false;
        }
        for &byte in bytes {
            if byte == b'\n' {
                if self.discard {
                    self.finish(
                        &Value::Null,
                        &json!({"status":"error","error":"line too long"}),
                    );
                } else if !self.line.is_empty() {
                    let request = serde_json::from_slice::<Value>(&self.line);
                    match request {
                        Ok(request) => {
                            let reply = self.command(&request);
                            self.finish(&request, &reply);
                        }
                        Err(_) => self.finish(
                            &Value::Null,
                            &json!({"status":"error","error":"invalid JSON"}),
                        ),
                    }
                }
                self.line.clear();
                self.discard = false;
            } else if !self.discard {
                if self.line.len() == MAX_LINE {
                    self.line.clear();
                    self.discard = true;
                } else {
                    self.line.push(byte);
                }
            }
        }
        true
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the JSON command is validated and applied as one atomic state transition"
    )]
    fn command(&mut self, request: &Value) -> Value {
        let id = &request["id"];
        if !id.is_i64() && !id.is_u64() {
            return json!({"id":null,"status":"error","error":"integer id required"});
        }
        let error = |why: &str| json!({"id":id,"status":"error","error":why});
        let Some(object) = request.as_object() else {
            return error("object required");
        };
        if object
            .keys()
            .any(|k| !matches!(k.as_str(), "id" | "system" | "ui"))
        {
            return error("unsupported command");
        }
        let mut reply = json!({"id":id,"status":"ok"});
        // ulcmd probes the serial application with an ID-only ping.
        if self.udm_pro && object.len() == 1 {
            return reply;
        }
        if let Some(system) = object.get("system") {
            let Some(system) = system.as_object() else {
                return error("system must be object");
            };
            if let Some(get) = system.get("get") {
                let udm_hash_probe = self.udm_pro
                    && get == "hash"
                    && system.len() == 2
                    && system.get("bootloader") == Some(&Value::Bool(true));
                if (system.len() != 1 && !udm_hash_probe) || object.contains_key("ui") {
                    return error("mixed query and update");
                }
                match get.as_str() {
                    Some("version") => {
                        reply["version"] = json!(if self.udm_pro {
                            "v2.5.7-0-gd26945b"
                        } else {
                            VERSION
                        });
                    }
                    Some("hash") => {
                        if self.udm_pro {
                            reply["target"] = json!("udm-gd-lcm-fw");
                        }
                        reply["md5"] = json!(if self.udm_pro {
                            "abbabb81f01cd6f25183f8369bc3aef6"
                        } else {
                            HASH
                        });
                    }
                    _ => return error("unsupported query"),
                }
                return reply;
            }
            // ulcmd returns to the application after verifying the emulated identity.
            if self.udm_pro
                && system.len() == 1
                && system.get("bootloader") == Some(&Value::Bool(false))
                && !object.contains_key("ui")
            {
                return reply;
            }
            // No fake success for firmware writes, erase, or bootloader entry.
            if system.keys().any(|k| {
                !matches!(
                    k.as_str(),
                    "screen"
                        | "state"
                        | "backlight"
                        | "brightness"
                        | "brightness.percent"
                        | "backlight.brightness"
                        | "orientation"
                        | "night.mode"
                        | "locate"
                        | "adopted"
                        | "color"
                        | "ar.seed"
                        | "set.clock"
                        | "set.clock.monotonic"
                        | "set.log.level"
                        | "communication"
                        | "touch"
                )
            }) {
                return error("unsupported system operation");
            }
        }
        if object.get("ui").is_some_and(|v| !v.is_object()) {
            return error("ui must be object");
        }
        if let Some(get) = request["ui"].get("get") {
            if get != "orientation"
                || request["ui"].as_object().is_none_or(|v| v.len() != 1)
                || object.contains_key("system")
            {
                return error("unsupported or mixed UI query");
            }
            self.orientation_event();
            return reply;
        }
        if let Some(orientation) = request["ui"].get("orientation")
            && !matches!(orientation.as_u64(), Some(0 | 90 | 180 | 270))
        {
            return error("invalid orientation");
        }
        if !object.contains_key("system") && !object.contains_key("ui") {
            return error("empty command");
        }
        let mut ui = self.ui.clone();
        let mut system = self.system.clone();
        if let Some(update) = request["ui"].as_object() {
            merge(&mut ui, update);
        }
        if let Some(update) = request["system"].as_object() {
            merge(&mut system, update);
        }
        if json!({"ui":ui,"system":system}).to_string().len() > MAX_STATE {
            return error("state capacity exceeded");
        }
        self.ui = ui;
        self.system = system;
        if request["ui"].get("orientation").is_some() {
            self.orientation_event();
        }
        reply
    }

    fn orientation_event(&mut self) {
        let orientation = self.ui.get("orientation").cloned().unwrap_or(json!(0));
        // Stock lcmd handles orientation before status: never combine this with ACK.
        self.replies.extend(
            json!({"orientation":orientation,
            "orientation.saved":orientation,"orientation.status":"ok"})
            .to_string()
            .bytes(),
        );
        self.replies.push_back(b'\n');
    }

    fn finish(&mut self, request: &Value, reply: &Value) {
        self.replies.extend(reply.to_string().bytes());
        self.replies.push_back(b'\n');
        self.publish(request, reply);
    }

    fn publish(&mut self, request: &Value, reply: &Value) {
        self.sequence = self.sequence.wrapping_add(1);
        self.snapshot = json!({"schema":"unifi.lcm.v1", "sequence":self.sequence,
            "kind":"state", "profile":if self.udm_pro { "udmpro-gd-2.5.7" } else { "us24pro-gd-5.4.4" }, "pixel_exact":false,
            "ui":self.ui,"system":self.system,"request":request,"reply":reply})
        .to_string()
        .into_bytes();
        self.snapshot.push(b'\n');
    }

    /// Drain reply bytes for the CDC bulk IN endpoint.
    pub fn read(&mut self, out: &mut [u8]) -> usize {
        let count = out.len().min(self.replies.len());
        for target in &mut out[..count] {
            if let Some(byte) = self.replies.pop_front() {
                *target = byte;
            }
        }
        count
    }

    /// Copy the newest complete snapshot, retaining it if the buffer is too small.
    /// Observability coalesces updates rather than backpressuring the guest.
    pub fn take_snapshot(&mut self, out: &mut [u8]) -> usize {
        let count = self.snapshot.len();
        if count > out.len() {
            return 0;
        }
        out[..count].copy_from_slice(&self.snapshot);
        self.snapshot.clear();
        count
    }
}

fn merge(target: &mut Map<String, Value>, update: &Map<String, Value>) {
    for (key, value) in update {
        if let (Some(Value::Object(old)), Value::Object(new)) = (target.get_mut(key), value) {
            merge(old, new);
        } else {
            target.insert(key.clone(), value.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn input_requires_initialized_display() {
        assert!(!Lcm::default().input(br#"{"screen":"menu.main"}"#));
    }
    #[test]
    fn port_input_orders_selection_before_screen_event() {
        let mut lcm = Lcm::default();
        transact(
            &mut lcm,
            json!({"id":1,"ui":{"communication":true,"state":"ready","screen":"menu.main"}}),
        );
        assert!(lcm.input(br#"{"port":24}"#));
        let mut bytes = [0; 256];
        let n = lcm.read(&mut bytes);
        assert_eq!(
            &bytes[..n],
            b"{\"port.id\":24}\n{\"screen.changed\":\"port\"}\n"
        );
    }
    #[test]
    fn input_rejects_control_actions_and_out_of_range_ports() {
        let mut lcm = Lcm::default();
        transact(
            &mut lcm,
            json!({"id":1,"ui":{"communication":true,"state":"ready","screen":"menu.main"}}),
        );
        for bytes in [
            br#"{"control":"reboot"}"#.as_slice(),
            br#"{"port":27}"#,
            br#"{"port":true}"#,
            br#"{"screen":"control"}"#,
        ] {
            assert!(!lcm.input(bytes));
        }
        assert!(lcm.replies.is_empty());
    }
    #[test]
    fn udm_pro_input_accepts_console_screens_without_a_pushed_screen() {
        let mut lcm = Lcm::udm_pro();
        transact(
            &mut lcm,
            json!({"id":1,"ui":{"communication":true,"state":"ready"}}),
        );
        assert!(lcm.input(br#"{"screen":"menu.network"}"#));
        let mut bytes = [0; 256];
        let n = lcm.read(&mut bytes);
        assert_eq!(&bytes[..n], b"{\"screen.changed\":\"menu.network\"}\n");
        assert_eq!(lcm.ui["screen"], "menu.network");
        let mut snapshot = [0; 4096];
        let n = lcm.take_snapshot(&mut snapshot);
        let frame: Value = serde_json::from_slice(&snapshot[..n]).unwrap();
        assert_eq!(frame["profile"], "udmpro-gd-2.5.7");
        assert_eq!(frame["request"], json!({"input":{"screen":"menu.network"}}));
        assert_eq!(frame["reply"], json!({"status":"queued"}));
    }
    #[test]
    fn udm_pro_input_rejects_switch_screens_ports_and_control() {
        let mut lcm = Lcm::udm_pro();
        transact(
            &mut lcm,
            json!({"id":1,"ui":{"communication":true,"state":"ready","screen":"menu.main"}}),
        );
        for bytes in [
            br#"{"screen":"menu.ports.type"}"#.as_slice(),
            br#"{"screen":"power"}"#,
            br#"{"port":1}"#,
            br#"{"control":"shutdown"}"#,
            br#"{"screensaver":"on"}"#,
            br#"{"dismiss":"wan.unplugged"}"#,
            br#"{"screen":"menu.network","screensaver":true}"#,
        ] {
            assert!(!lcm.input(bytes), "{}", String::from_utf8_lossy(bytes));
        }
        assert!(lcm.replies.is_empty());
        assert_eq!(lcm.ui["screen"], "menu.main");
    }
    #[test]
    fn udm_pro_input_requires_ready_state() {
        let mut lcm = Lcm::udm_pro();
        transact(
            &mut lcm,
            json!({"id":1,"ui":{"communication":true,"state":"boot"}}),
        );
        assert!(!lcm.input(br#"{"screen":"menu.main"}"#));
    }
    #[test]
    fn udm_pro_screensaver_and_warning_dismiss_emit_daemon_events() {
        let mut lcm = Lcm::udm_pro();
        transact(
            &mut lcm,
            json!({"id":1,"ui":{"communication":true,"state":"ready",
                "warnings":{"wan.unplugged":{"dismiss":false}}}}),
        );
        assert!(lcm.input(br#"{"screensaver":true}"#));
        assert!(lcm.input(br#"{"dismiss":"wan.unplugged"}"#));
        assert!(!lcm.input(br#"{"dismiss":"disk.at.risk"}"#));
        let mut bytes = [0; 256];
        let n = lcm.read(&mut bytes);
        assert_eq!(
            &bytes[..n],
            b"{\"screensaver\":true}\n{\"warning.dismiss\":\"wan.unplugged\"}\n"
        );
        assert_eq!(lcm.ui["screensaver"], true);
        assert!(!lcm.ui.contains_key("screen"));
        assert_eq!(lcm.ui["warnings"]["wan.unplugged"]["dismiss"], false);
    }
    #[test]
    fn us24pro_input_still_requires_a_screen() {
        let mut lcm = Lcm::default();
        transact(
            &mut lcm,
            json!({"id":1,"ui":{"communication":true,"state":"ready"}}),
        );
        assert!(!lcm.input(br#"{"screen":"menu.main"}"#));
        assert!(!lcm.input(br#"{"screensaver":true}"#));
    }
    #[test]
    fn orientation_query_emits_event_then_separate_ack() {
        let mut lcm = Lcm::default();
        assert!(lcm.feed(b"{\"id\":6,\"ui\":{\"get\":\"orientation\"}}\n"));
        let mut bytes = [0; 512];
        let n = lcm.read(&mut bytes);
        let frames: Vec<Value> = bytes[..n]
            .split(|b| *b == b'\n')
            .filter(|s| !s.is_empty())
            .map(|s| serde_json::from_slice(s).unwrap())
            .collect();
        assert_eq!(
            frames,
            vec![
                json!({"orientation":0,"orientation.saved":0,"orientation.status":"ok"}),
                json!({"id":6,"status":"ok"})
            ]
        );
        assert!(!lcm.ui.contains_key("get"));
    }
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the test helper accepts owned JSON values for concise call sites"
    )]
    fn transact(lcm: &mut Lcm, request: Value) -> Value {
        let wire = format!("{request}\n");
        for chunk in wire.as_bytes().chunks(7) {
            assert!(lcm.feed(chunk));
        }
        let mut out = [0; 8192];
        let count = lcm.read(&mut out);
        serde_json::from_slice(&out[..count]).unwrap()
    }
    #[test]
    fn fragmented_version_query_returns_profile_and_matching_id() {
        assert_eq!(
            transact(
                &mut Lcm::default(),
                json!({"id":1,"system":{"get":"version"}})
            ),
            json!({"id":1,"status":"ok","version":VERSION})
        );
    }
    #[test]
    fn hash_query_returns_md5_field() {
        assert_eq!(
            transact(&mut Lcm::default(), json!({"id":2,"system":{"get":"hash"}}))["md5"],
            HASH
        );
    }
    #[test]
    fn udm_identity_survives_usb_reset() {
        let mut lcm = Lcm::udm_pro();
        lcm.reset();
        assert_eq!(
            transact(&mut lcm, json!({"id":42})),
            json!({"id":42,"status":"ok"})
        );
        assert_eq!(
            transact(&mut lcm, json!({"id":1,"system":{"get":"version"}}))["version"],
            "v2.5.7-0-gd26945b"
        );
        assert_eq!(
            transact(&mut lcm, json!({"id":2,"system":{"get":"hash"}}))["md5"],
            "abbabb81f01cd6f25183f8369bc3aef6"
        );
    }
    #[test]
    fn udm_hash_handshake_accepts_probe_but_rejects_firmware_entry() {
        let mut lcm = Lcm::udm_pro();
        let probe = json!({"id":8,"system":{"get":"hash","bootloader":true}});
        assert_eq!(
            transact(&mut lcm, probe.clone()),
            json!({
                "id":8,"status":"ok","target":"udm-gd-lcm-fw",
                "md5":"abbabb81f01cd6f25183f8369bc3aef6"
            })
        );
        assert_eq!(transact(&mut Lcm::default(), probe)["status"], "error");
        assert_eq!(
            transact(&mut lcm, json!({"id":9,"system":{"bootloader":false}}))["status"],
            "ok"
        );
        assert_eq!(
            transact(&mut lcm, json!({"id":10,"system":{"bootloader":true}}))["status"],
            "error"
        );
    }
    #[test]
    fn ui_updates_merge_port_objects_and_telemetry() {
        let mut lcm = Lcm::default();
        transact(
            &mut lcm,
            json!({"id":3,"ui":{"ports":{"1":{"speed":1000}},"usage.cpu":3}}),
        );
        transact(
            &mut lcm,
            json!({"id":4,"ui":{"ports":{"2":{"speed":0}},"usage.mem":7}}),
        );
        assert_eq!(lcm.ui["ports"].as_object().unwrap().len(), 2);
        assert_eq!(lcm.ui["usage.cpu"], 3);
    }
    #[test]
    fn unsupported_flash_is_not_acknowledged() {
        assert_eq!(
            transact(&mut Lcm::default(), json!({"id":7,"system":{"erase":true}}))["status"],
            "error"
        );
    }
    #[test]
    fn invalid_id_does_not_change_state() {
        let mut lcm = Lcm::default();
        transact(&mut lcm, json!({"id":"1","ui":{"usage.cpu":90}}));
        assert!(lcm.ui.is_empty());
    }
    #[test]
    fn overlong_line_recovers_at_newline() {
        let mut lcm = Lcm::default();
        for _ in 0..100 {
            assert!(lcm.feed(&[b'x'; 64]));
        }
        assert!(lcm.feed(b"\n"));
        lcm.read(&mut [0; 8192]);
        assert_eq!(transact(&mut lcm, json!({"id":8,"ui":{}}))["status"], "ok");
    }
    #[test]
    fn reset_clears_reply_and_ui() {
        let mut lcm = Lcm::default();
        transact(&mut lcm, json!({"id":1,"ui":{"screen":"ports"}}));
        lcm.reset();
        assert!(lcm.ui.is_empty() && lcm.replies.is_empty());
    }
    #[test]
    fn xhci_bulk_transfer_accepts_complete_screen_message() {
        let mut lcm = Lcm::udm_pro();
        let request = json!({"id":783_368_690,"ui":{"backlight.brightness":80,
            "board.revision":10,"color":"0139FF","mac":"52:54:00:4D:50:01",
            "screen.timeout":300,"update.time":100}});
        let wire = request.to_string() + "\n";
        assert!(wire.len() > 64);
        assert!(lcm.feed(wire.as_bytes()));
        assert_eq!(lcm.ui["screen.timeout"], 300);
        let mut out = [0; 256];
        let size = lcm.read(&mut out);
        assert_eq!(
            serde_json::from_slice::<Value>(&out[..size]).unwrap(),
            json!({"id":783_368_690,"status":"ok"})
        );
    }
    #[test]
    fn bulk_backpressure_reserves_all_replies_without_partial_updates() {
        let mut lcm = Lcm::udm_pro();
        lcm.replies.resize(MAX_QUEUE - 256, 0);
        assert!(!lcm.feed(b"{\"id\":1,\"ui\":{\"state\":\"boot\"}}\n{\"id\":2}\n"));
        assert!(lcm.ui.is_empty());
        assert!(lcm.line.is_empty());
        assert_eq!(lcm.replies.len(), MAX_QUEUE - 256);
    }
    #[test]
    fn backpressure_rejects_packet_without_mutation() {
        let mut lcm = Lcm::default();
        lcm.replies.resize(MAX_QUEUE, 0);
        assert!(!lcm.feed(b"{}\n"));
        assert!(lcm.line.is_empty());
    }
}
