//! Flow state machine.
//!
//! Tracks per-flow packet metadata and parses TLS record headers to extract
//! Application Data record lengths.

use std::net::Ipv4Addr;

pub const MAX_PKT_SAMPLES: usize = 5_000;
const MAX_TLS_RECORDS: usize = 200;
const MAX_TLS_BUF: usize = 4 * 1024 * 1024;

pub const MCP_IP: Ipv4Addr = Ipv4Addr::new(10, 11, 0, 10);
pub const MCP_PORT: u16 = 8440;
pub const NOISE_IP: Ipv4Addr = Ipv4Addr::new(10, 11, 0, 20);
pub const NOISE_PORT: u16 = 9443;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Up,   // client → server
    Down, // server → client
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: u32,
    pub src_port: u16,
    pub dst_ip: u32,
    pub dst_port: u16,
}

impl FlowKey {
    pub fn new(src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16) -> Self {
        Self { src_ip, src_port, dst_ip, dst_port }
    }

    pub fn display(&self) -> String {
        let src = Ipv4Addr::from(self.src_ip);
        let dst = Ipv4Addr::from(self.dst_ip);
        format!("{}:{} → {}:{}", src, self.src_port, dst, self.dst_port)
    }
}

#[derive(Debug, Clone)]
pub struct PacketRecord {
    pub ts: f64,
    pub direction: Direction,
    pub payload_len: usize,
}

#[derive(Debug)]
#[derive(Clone)]
pub struct Flow {
    pub key: FlowKey,
    pub start_ts: f64,
    pub end_ts: f64,

    pub pkts: Vec<PacketRecord>,

    pub tls_appdata_up: Vec<u16>,
    pub tls_appdata_down: Vec<u16>,

    tls_buf_up: Vec<u8>,
    tls_buf_down: Vec<u8>,

    seen_appdata: bool,
    pub last_pkt_ts: f64,

    pub first_payload_entropy: f64,
}

impl Flow {
    pub fn new(key: FlowKey, ts: f64) -> Self {
        Self {
            key,
            start_ts: ts,
            end_ts: ts,
            pkts: Vec::new(),
            tls_appdata_up: Vec::new(),
            tls_appdata_down: Vec::new(),
            tls_buf_up: Vec::new(),
            tls_buf_down: Vec::new(),
            seen_appdata: false,
            last_pkt_ts: ts,
            first_payload_entropy: 0.0,
        }
    }

    pub fn add_packet(&mut self, ts: f64, direction: Direction, payload: &[u8]) {
        self.end_ts = ts;
        self.last_pkt_ts = ts;

        if self.seen_appdata && self.pkts.is_empty() && !payload.is_empty() {
            let take_len = std::cmp::min(payload.len(), 64);
            self.first_payload_entropy = shannon_entropy(&payload[..take_len]);
        }

        if self.seen_appdata && self.pkts.len() < MAX_PKT_SAMPLES {
            self.pkts.push(PacketRecord {
                ts,
                direction,
                payload_len: payload.len(),
            });
        }

        match direction {
            Direction::Up => {
                self.tls_buf_up.extend_from_slice(payload);
                Self::parse_tls(
                    &mut self.tls_buf_up,
                    &mut self.tls_appdata_up,
                    &mut self.seen_appdata,
                );
            }
            Direction::Down => {
                self.tls_buf_down.extend_from_slice(payload);
                Self::parse_tls(
                    &mut self.tls_buf_down,
                    &mut self.tls_appdata_down,
                    &mut self.seen_appdata,
                );
            }
        }
    }

    fn parse_tls(buf: &mut Vec<u8>, out_records: &mut Vec<u16>, seen_appdata: &mut bool) {
        let mut pos = 0;

        while pos + 5 <= buf.len() {
            let rec_type = buf[pos];

            if !(20..=23).contains(&rec_type) {
                pos += 1;
                if buf.len() - pos > MAX_TLS_BUF {
                    let half = MAX_TLS_BUF / 2;
                    let new_start = buf.len() - half;
                    buf.drain(..new_start);
                    pos = 0;
                }
                continue;
            }

            let rec_len = u16::from_be_bytes([buf[pos + 3], buf[pos + 4]]) as usize;
            let total = 5 + rec_len;

            if pos + total > buf.len() {
                break;
            }

            if rec_type == 23 {
                if out_records.len() < MAX_TLS_RECORDS {
                    out_records.push(rec_len as u16);
                }
                if !*seen_appdata {
                    *seen_appdata = true;
                }
            }

            pos += total;
        }

        if pos > 0 {
            buf.drain(..pos);
        }
    }

    pub fn pkt_count(&self) -> usize {
        self.pkts.len()
    }

    pub fn ground_truth_label(&self) -> Option<u8> {
        let dport = self.key.dst_port;
        let sport = self.key.src_port;

        // Label map based on port
        // 8440: fetch (1)
        // 8441: memory (2)
        // 8442: filesystem (3)
        // 8443: github (4)
        // 8444: exa (5)
        // 8445: tavily (6)
        // 9443: noise (0)

        if dport == 9443 || sport == 9443 {
            return Some(0);
        } else if dport == 8440 || sport == 8440 {
            return Some(1);
        } else if dport == 8441 || sport == 8441 {
            return Some(2);
        } else if dport == 8442 || sport == 8442 {
            return Some(3);
        } else if dport == 8443 || sport == 8443 {
            return Some(4);
        } else if dport == 8444 || sport == 8444 {
            return Some(5);
        } else if dport == 8445 || sport == 8445 {
            return Some(6);
        }

        None
    }
}

pub fn is_server_endpoint(_ip: u32, port: u16) -> bool {
    (8440..=8445).contains(&port) || port == 9443
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let mut entropy = 0.0;
    let len = data.len() as f64;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}
