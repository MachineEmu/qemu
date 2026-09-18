//! Optional nonblocking host adapter. Never registered with the host medium here.
use super::{Board, UnifiBoard, UnifiExecutionResult, UnifiHost, execute};
use board_core::MachineContext;
use mt7981_machine::{Mt7981Board, WifiRxInfo};
use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::ffi::{CStr, c_char};
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

const LINE: usize = 16384;
const LIMIT: usize = 256;

/// Opaque, separately owned hwsim socket frontend; QEMU serializes all accesses.
pub struct UnifiWifi {
    socket: UnixStream,
    input: Vec<u8>,
    output: VecDeque<Vec<u8>>,
    written: usize,
    radios: [bool; 2],
    ready: bool,
    next_id: u64,
    pending: HashMap<u64, (Instant, Option<u16>)>,
    connected: Instant,
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid hwsim protocol message")
}

impl UnifiWifi {
    fn new(socket: UnixStream) -> io::Result<Self> {
        socket.set_nonblocking(true)?;
        Ok(Self {
            socket,
            input: Vec::new(),
            output: VecDeque::new(),
            written: 0,
            radios: [false; 2],
            ready: false,
            next_id: 1,
            pending: HashMap::new(),
            connected: Instant::now(),
        })
    }

    fn send(&mut self, message: Value) -> io::Result<()> {
        if self.output.len() >= LIMIT {
            return Err(invalid());
        }
        let mut bytes = serde_json::to_vec(&message)?;
        bytes.push(b'\n');
        if bytes.len() > LINE {
            return Err(invalid());
        }
        self.output.push_back(bytes);
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        while let Some(front) = self.output.front() {
            match self.socket.write(&front[self.written..]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => {
                    self.written += n;
                    if self.written == front.len() {
                        self.output.pop_front();
                        self.written = 0;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn message(
        &mut self,
        board: &mut Mt7981Board,
        ctx: &mut MachineContext<'_>,
        p: &Value,
    ) -> io::Result<()> {
        if p["version"].as_u64() != Some(1) {
            return Err(invalid());
        }
        match p["type"].as_str() {
            Some("ready") if !self.ready && p["frontend"] == "raw-80211" => {
                let list = p["radios"].as_array().ok_or_else(invalid)?;
                if list.is_empty() || list.len() > 2 {
                    return Err(invalid());
                }
                let mut radios = [false; 2];
                for radio in list {
                    let band = match radio.as_str() {
                        Some("band0") => 0,
                        Some("band1") => 1,
                        _ => return Err(invalid()),
                    };
                    if radios[band] {
                        return Err(invalid());
                    }
                    radios[band] = true;
                }
                self.radios = radios;
                self.ready = true;
                board.wifi_online(radios);
            }
            Some("rx") => {
                let id = p["id"].as_u64().ok_or_else(invalid)?;
                let band = match p["radio"].as_str() {
                    Some("band0") => 0,
                    Some("band1") => 1,
                    _ => return Err(invalid()),
                };
                let mhz = p["frequency"]
                    .as_u64()
                    .and_then(|v| u32::try_from(v).ok())
                    .ok_or_else(invalid)?;
                let signal = p["signal"]
                    .as_i64()
                    .and_then(|v| i32::try_from(v).ok())
                    .ok_or_else(invalid)?;
                let rate_index = p.get("rate").and_then(Value::as_u64).unwrap_or(0);
                let rate_index = u8::try_from(rate_index)
                    .ok()
                    .filter(|rate| *rate < 32)
                    .ok_or_else(invalid)?;
                let aggregate = p
                    .get("aggregate")
                    .map(Value::as_bool)
                    .unwrap_or(Some(false))
                    .ok_or_else(invalid)?;
                let flags = p["flags"].as_u64().ok_or_else(invalid)?;
                let frame =
                    hex::decode(p["frame"].as_str().ok_or_else(invalid)?).map_err(|_| invalid())?;
                if !(24..=2304).contains(&frame.len()) {
                    return Err(invalid());
                }
                // Registration may deliver RX before ready. Reject it explicitly.
                let delivered = self.ready
                    && self.radios[usize::from(band)]
                    && board.wifi_rx(
                        ctx,
                        WifiRxInfo {
                            band,
                            frequency: mhz,
                            signal_dbm: signal,
                            rate_index,
                            aggregate,
                        },
                        &frame,
                    );
                let acked = delivered && frame[4] & 1 == 0 && flags & 2 == 0;
                self.send(json!({"version":1,"type":"rx-status","id":id,"acked":acked}))?;
            }
            Some("injected") => {
                let id = p["id"].as_u64().ok_or_else(invalid)?;
                let accepted = p["accepted"].as_bool().ok_or_else(invalid)?;
                let Some((_, station)) = self.pending.remove(&id) else {
                    return Err(invalid());
                };
                board.wifi_tx_result(station, accepted);
                // Injection acceptance is not a wireless ACK. No TX success event.
            }
            _ => return Err(invalid()),
        }
        Ok(())
    }

    fn poll(&mut self, board: &mut Mt7981Board, ctx: &mut MachineContext<'_>) -> io::Result<()> {
        if (!self.ready && self.connected.elapsed() > Duration::from_secs(5))
            || self
                .pending
                .values()
                .any(|(t, _)| t.elapsed() > Duration::from_secs(5))
        {
            return Err(io::ErrorKind::TimedOut.into());
        }
        self.flush()?;
        // Limit work per callback even when a peer continuously sends data.
        for _ in 0..LIMIT {
            if let Some(end) = self.input.iter().position(|b| *b == b'\n') {
                let message: Value = serde_json::from_slice(&self.input[..end])?;
                self.input.drain(..=end);
                self.message(board, ctx, &message)?;
                continue;
            }
            let mut buf = [0; 4096];
            let capacity = (LINE - self.input.len()).min(buf.len());
            if capacity == 0 {
                return Err(invalid());
            }
            match self.socket.read(&mut buf[..capacity]) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(n) => self.input.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        board.wifi_online(self.radios);
        board.wifi_poll(ctx);
        while self.pending.len() < LIMIT && self.output.len() < LIMIT {
            let Some(packet) = board.wifi_take_tx() else {
                break;
            };
            let id = self.next_id;
            self.next_id = id.checked_add(1).ok_or_else(invalid)?;
            self.send(json!({"version":1,"type":"tx","id":id,
                "radio":format!("band{}",packet.band),"frequency":packet.frequency,
                "frame":hex::encode(packet.frame),"rate":packet.rate_index,
                "aggregate":packet.aggregate}))?;
            self.pending.insert(id, (Instant::now(), packet.station));
        }
        self.flush()
    }
}

/// Connect an explicitly requested local hwsim frontend. Null means failure.
/// # Safety
/// `path` must point to a live NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unifi_wifi_new(path: *const c_char) -> *mut UnifiWifi {
    if path.is_null() {
        return std::ptr::null_mut();
    }
    let path = unsafe { CStr::from_ptr(path) };
    let Ok(path) = path.to_str() else {
        return std::ptr::null_mut();
    };
    match UnixStream::connect(path).and_then(UnifiWifi::new) {
        Ok(wifi) => Box::into_raw(Box::new(wifi)),
        Err(e) => {
            eprintln!("hwsim connect: {e}");
            std::ptr::null_mut()
        }
    }
}

/// Release the socket, relinquishing the backend connection.
/// # Safety
/// `wifi` must be null or an unfreed pointer returned by `unifi_wifi_new`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unifi_wifi_free(wifi: *mut UnifiWifi) {
    if !wifi.is_null() {
        drop(unsafe { Box::from_raw(wifi) });
    }
}

/// Poll without blocking. Returns false on disconnect/protocol failure.
/// # Safety
/// Pointers must refer to live, exclusively borrowed ABI objects and callbacks.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unifi_wifi_poll(
    wifi: *mut UnifiWifi,
    board: *mut UnifiBoard,
    host: *const UnifiHost,
    out: *mut UnifiExecutionResult,
) -> bool {
    let Some(wifi) = (unsafe { wifi.as_mut() }) else {
        return false;
    };
    let mut alive = false;
    unsafe {
        execute(
            board,
            host,
            out,
            "wifi-poll",
            None,
            None,
            None,
            |board, ctx| {
                if let Board::Mt7981(board) = board {
                    match wifi.poll(board, ctx) {
                        Ok(()) => alive = true,
                        Err(e) => {
                            board.wifi_online([false; 2]);
                            eprintln!("hwsim disconnected: {e}");
                        }
                    }
                }
                Ok(0)
            },
            None,
        );
    }
    alive
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_is_strict_and_registration_rx_is_negative() {
        let (a, _b) = UnixStream::pair().unwrap();
        let mut wifi = UnifiWifi::new(a).unwrap();
        let mut board = Mt7981Board::new();
        let mut ctx = MachineContext::new(0);
        let rx = json!({"version":1,"type":"rx","id":1,"radio":"band0","frequency":2412,
            "signal":-40,"flags":0,"frame":hex::encode([0u8; 24])});
        wifi.message(&mut board, &mut ctx, &rx).unwrap();
        let status: Value = serde_json::from_slice(wifi.output.front().unwrap()).unwrap();
        assert_eq!(status["acked"], false);
        for list in [json!([]), json!(["band0", "band0"]), json!(["other"])] {
            assert!(
                wifi.message(
                    &mut board,
                    &mut ctx,
                    &json!({"version":1,"type":"ready",
                "frontend":"raw-80211","radios":list})
                )
                .is_err()
            );
            assert!(!wifi.ready);
        }
    }

    #[test]
    fn output_queue_is_bounded_and_partial_write_offset_is_preserved() {
        let (a, mut b) = UnixStream::pair().unwrap();
        let mut wifi = UnifiWifi::new(a).unwrap();
        let message = json!({"version":1,"type":"tx","frame":"ab".repeat(2304)});
        for _ in 0..LIMIT {
            wifi.send(message.clone()).unwrap();
        }
        assert!(wifi.send(message.clone()).is_err());
        assert_eq!(wifi.output.len(), LIMIT);
        // Simulate a prior partial write; the remainder must have no repeated prefix.
        wifi.output.clear();
        wifi.send(message).unwrap();
        wifi.written = 17;
        let expected = wifi.output[0][17..].to_vec();
        wifi.flush().unwrap();
        let mut received = vec![0; expected.len()];
        b.read_exact(&mut received).unwrap();
        assert_eq!(received, expected);
        assert_eq!(wifi.written, 0);
    }

    #[test]
    fn handshake_and_injection_timeouts_terminate_poll() {
        for ready in [false, true] {
            let (a, _b) = UnixStream::pair().unwrap();
            let mut wifi = UnifiWifi::new(a).unwrap();
            wifi.connected = Instant::now() - Duration::from_secs(6);
            wifi.ready = ready;
            if ready {
                wifi.pending.insert(1, (wifi.connected, None));
            }
            let error = wifi
                .poll(&mut Mt7981Board::new(), &mut MachineContext::new(0))
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        }
    }

    #[test]
    fn injected_status_never_manufactures_guest_completion() {
        let (a, _b) = UnixStream::pair().unwrap();
        let mut wifi = UnifiWifi::new(a).unwrap();
        let mut board = Mt7981Board::new();
        let mut ctx = MachineContext::new(0);
        for accepted in [false, true] {
            wifi.pending.insert(1, (Instant::now(), None));
            let response = json!({"version":1,"type":"injected","id":1,"accepted":accepted});
            wifi.message(&mut board, &mut ctx, &response).unwrap();
            assert!(ctx.events.is_empty());
            assert!(wifi.message(&mut board, &mut ctx, &response).is_err());
        }
    }
}
