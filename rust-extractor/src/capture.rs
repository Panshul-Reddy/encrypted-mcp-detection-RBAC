//! Packet capture layer.
//!
//! Provides live capture and PCAP file replay using the `pcap` crate.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use dashmap::DashMap;
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use tracing::{debug, info};

use crate::flow::{Direction, Flow, FlowKey, is_server_endpoint};

pub type FlowTable = Arc<DashMap<FlowKey, Flow>>;

/// Capture statistics updated atomically.
#[derive(Debug, Default)]
pub struct CaptureStats {
    pub packets_total: std::sync::atomic::AtomicU64,
    pub packets_matched: std::sync::atomic::AtomicU64,
    pub flows_created: std::sync::atomic::AtomicU64,
    pub flows_restarted: std::sync::atomic::AtomicU64,
}

impl CaptureStats {
    pub fn packets_total(&self) -> u64 {
        self.packets_total
            .load(std::sync::atomic::Ordering::Relaxed)
    }
    pub fn packets_matched(&self) -> u64 {
        self.packets_matched
            .load(std::sync::atomic::Ordering::Relaxed)
    }
    pub fn flows_created(&self) -> u64 {
        self.flows_created
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Open a live capture on the given interface.
pub fn open_live(
    interface: &str,
    bpf_filter: &str,
) -> Result<pcap::Capture<pcap::Active>> {
    info!(interface, bpf_filter, "Opening live capture");
    let cap = pcap::Capture::from_device(interface)
        .context("Failed to open capture device")?
        .promisc(true)
        .snaplen(65535)
        .buffer_size(128 * 1024 * 1024) // 128 MB ring buffer
        .timeout(100) // 100ms read timeout for non-blocking behavior
        .open()
        .context("Failed to activate capture")?;

    let mut cap = cap;
    cap.filter(bpf_filter, true)
        .context("Failed to apply BPF filter")?;

    Ok(cap)
}

/// Open a PCAP file for offline replay.
pub fn open_offline(path: &Path) -> Result<pcap::Capture<pcap::Offline>> {
    info!(path = %path.display(), "Opening PCAP file for replay");


    let is_gzip = {
        let mut f = std::fs::File::open(path).context("Failed to open PCAP file")?;
        let mut magic = [0u8; 2];
        use std::io::Read;
        f.read_exact(&mut magic).ok();
        magic == [0x1f, 0x8b]
    };

    if is_gzip {

        use flate2::read::GzDecoder;
        use std::io::{Read, Write};

        let gz_file = std::fs::File::open(path)?;
        let mut decoder = GzDecoder::new(gz_file);
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .context("Failed to decompress .pcap.gz")?;


        // Use a PID-suffixed temp path to prevent collision when two
        // replay processes decompress different .pcap.gz files simultaneously.
        let tmp_path = path.with_extension(format!("{}.tmp.pcap", std::process::id()));
        let mut tmp_file = std::fs::File::create(&tmp_path)?;
        tmp_file.write_all(&decompressed)?;
        drop(tmp_file);

        let cap = pcap::Capture::from_file(&tmp_path)
            .context("Failed to open decompressed PCAP")?;


        let _ = std::fs::remove_file(&tmp_path);

        Ok(cap)
    } else {
        pcap::Capture::from_file(path).context("Failed to open PCAP file")
    }
}

/// Process packets from any capture source into the flow table.
/// Calls `on_flow_restart` when a SYN is seen on an existing flow key.
///
/// Returns the number of packets processed.
pub fn process_packets<C: pcap::Activated>(
    cap: &mut pcap::Capture<C>,
    flow_table: &FlowTable,
    stats: &CaptureStats,
    on_flow_restart: &mut dyn FnMut(Flow),
    on_early_emit: &mut dyn FnMut(Flow),
) -> u64 {
    let mut pkt_count = 0u64;

    while let Ok(packet) = cap.next_packet() {
        pkt_count += 1;
        stats
            .packets_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let ts = packet.header.ts.tv_sec as f64
            + packet.header.ts.tv_usec as f64 / 1_000_000.0;


        let parsed = match SlicedPacket::from_ethernet(packet.data) {
            Ok(p) if p.net.is_some() => p,
            _ => {
                // macOS lo0 fallback (4-byte loopback header)
                if packet.data.len() > 4 {
                    match SlicedPacket::from_ip(&packet.data[4..]) {
                        Ok(p) => p,
                        Err(_) => continue,
                    }
                } else {
                    continue;
                }
            }
        };


        let (src_ip, dst_ip) = match &parsed.net {
            Some(NetSlice::Ipv4(ipv4)) => {
                let src = u32::from_be_bytes(ipv4.header().source());
                let dst = u32::from_be_bytes(ipv4.header().destination());
                (src, dst)
            }
            Some(NetSlice::Ipv6(ipv6)) => {

                let src = u32::from_be_bytes(ipv6.header().source()[12..16].try_into().unwrap());
                let dst = u32::from_be_bytes(ipv6.header().destination()[12..16].try_into().unwrap());
                (src, dst)
            }
            _ => continue,
        };


        let (sport, dport, is_syn_no_ack, payload) = match &parsed.transport {
            Some(TransportSlice::Tcp(tcp)) => {
                let syn_no_ack = tcp.syn() && !tcp.ack();
                (tcp.source_port(), tcp.destination_port(), syn_no_ack, tcp.payload())
            }
            _ => continue,
        };


        let (key, direction) = if is_server_endpoint(dst_ip, dport) {
            (FlowKey::new(src_ip, sport, dst_ip, dport), Direction::Up)
        } else if is_server_endpoint(src_ip, sport) {
            (FlowKey::new(dst_ip, dport, src_ip, sport), Direction::Down)
        } else {
            continue;
        };

        stats
            .packets_matched
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);


        let is_syn_start = is_syn_no_ack;
        if is_syn_start {
            if let Some((_, old_flow)) = flow_table.remove(&key) {
                stats
                    .flows_restarted
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                on_flow_restart(old_flow);
            }
        }

        let mut emit_early = false;
        let mut entry = flow_table.entry(key).or_insert_with(|| {
            stats
                .flows_created
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            debug!(flow = %key.display(), "New flow");
            Flow::new(key, ts)
        });

        if !payload.is_empty() {
            entry.add_packet(ts, direction, payload);
            let count = entry.pkt_count();
            if count == 3 || count == 5 || count == 8 || count == 10 || count == 15 || count == 20 {
                emit_early = true;
            }
        } else {
            entry.last_pkt_ts = ts;
            entry.end_ts = ts;
        }

        if emit_early {
            let flow_clone = entry.value().clone();
            on_early_emit(flow_clone);
        }
    }

    pkt_count
}

/// List available network interfaces.
pub fn list_interfaces() -> Result<Vec<pcap::Device>> {
    pcap::Device::list().context("Failed to list network interfaces")
}
