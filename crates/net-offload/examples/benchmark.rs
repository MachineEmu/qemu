//! Packet-engine microbenchmark; excludes TAP, host networking and guest CPU.
use net_offload::{IP_CHECKSUM, Request, TCP_CHECKSUM, TSO, UDP_CHECKSUM, prepare};
use std::{hint::black_box, time::Instant};
#[expect(
    clippy::cast_possible_truncation,
    reason = "fixed benchmark fixtures fit IP length fields"
)]
fn packet(payload: usize, udp: bool) -> Vec<u8> {
    let mut frame = vec![0x5a; 14 + 20 + if udp { 8 } else { 20 } + payload];
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    frame[14..34].fill(0);
    frame[14] = 0x45;
    let total = (frame.len() - 14) as u16;
    frame[16..18].copy_from_slice(&total.to_be_bytes());
    frame[22] = 64;
    frame[23] = if udp { 17 } else { 6 };
    frame[26..34].copy_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
    if udp {
        frame[38..40].copy_from_slice(&((payload + 8) as u16).to_be_bytes());
    } else {
        frame[46] = 0x50;
        frame[47] = 0x18;
    }
    frame
}
fn main() {
    let iterations: usize = std::env::args()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000);
    for (name, payload, udp, tso) in [
        ("udp-1400", 1400, true, false),
        ("tcp-tso-16000", 16000, false, true),
        ("tcp-tso-60000", 60000, false, true),
    ] {
        let input = packet(payload, udp);
        let req = Request {
            flags: IP_CHECKSUM
                | if udp { UDP_CHECKSUM } else { TCP_CHECKSUM }
                | if tso { TSO } else { 0 },
            mss: if tso { 1460 } else { 0 },
            ..Request::default()
        };
        for trial in 0..7 {
            for index in 0..2 {
                let caps = if (trial + index) % 2 == 0 { 0 } else { 7 };
                let mut packets = 0;
                let start = Instant::now();
                for _ in 0..iterations {
                    let batch = prepare(black_box(req), black_box(input.clone()), caps)
                        .expect("valid fixture");
                    packets += batch.packets.len();
                    black_box(batch);
                }
                let ns = start.elapsed().as_nanos();
                println!(
                    "{{\"case\":\"{name}\",\"mode\":\"{}\",\"trial\":{trial},\"iterations\":{iterations},\"input_bytes\":{},\"output_packets\":{packets},\"elapsed_ns\":{ns}}}",
                    if caps == 0 {
                        "software"
                    } else {
                        "virtio-offload"
                    },
                    input.len()
                );
            }
        }
    }
}
