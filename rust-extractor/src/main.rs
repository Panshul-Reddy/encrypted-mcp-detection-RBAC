//! Live MCP Traffic Analyzer
//!
//! Captures packets from a network interface or PCAP files, extracts features,
//! queries the inference sidecar for classification, and displays results in a TUI.
//!
//! Usage:
//!   # Live capture
//!   sudo cargo run -- --interface bridge100 --inference-url http://localhost:5000
//!
//!   # PCAP replay
//!   cargo run -- --replay ./capture/*.pcap.gz --inference-url http://localhost:5000


//! FastFlow Live Analyzer & Dataset Extractor
//!
//! This serves as the core entry point for the high-speed Rust packet processing engine.
//! It leverages `libpcap` to capture raw network traffic in promiscuous mode, performing 
//! line-rate TCP stream reassembly and TLS unencrypted header parsing. 
//! 
//! The analyzer can be run in two modes:
//! - **Dataset Generation**: Emits a comprehensive CSV of network features across all flows.
//! - **Live Inference**: Continuously dispatches N-packet feature sequences to the 
//!   asynchronous FastFlow Python API, acting dynamically upon terminal classifications 
//!   by transmitting out-of-band UDP KILL commands to the TLS enforcement proxy.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::Result;
use clap::Parser;
use tokio::sync::{mpsc, watch};
use tracing::{error, info, warn};

use live_analyzer::capture::{self, CaptureStats, FlowTable};
use live_analyzer::features::extract_features;
use live_analyzer::inference::{InferenceClient, InferenceConfig};
use live_analyzer::reaper::{self, FinalizedFlow, ReaperConfig};
use live_analyzer::tui::{self, ClassifiedFlow, TuiState};

/// Live MCP traffic analyzer.
#[derive(Parser, Debug)]
#[command(name = "live-analyzer", version, about)]
struct Args {
    /// Network interface for live capture (e.g., bridge100, en0).
    #[arg(short, long)]
    interface: Option<String>,

    /// PCAP file(s) for offline replay (supports .pcap and .pcap.gz).
    #[arg(short, long, num_args = 1..)]
    replay: Option<Vec<PathBuf>>,

    /// BPF filter expression.
    #[arg(short, long, default_value = "tcp port 8440 or tcp port 8441 or tcp port 8442 or tcp port 8443 or tcp port 8444 or tcp port 8445 or tcp port 9443")]
    bpf_filter: String,

    /// Inference sidecar URL.
    #[arg(long, default_value = "http://localhost:5000")]
    inference_url: String,

    /// Flow idle timeout in seconds.
    #[arg(long, default_value = "30")]
    idle_timeout: f64,

    /// Minimum packets for a flow to be classifiable.
    #[arg(long, default_value = "6")]
    min_pkts: usize,

    /// List available network interfaces and exit.
    #[arg(long)]
    list_interfaces: bool,

    /// Export extracted features to a CSV file (disables inference).
    #[arg(long)]
    export_csv: Option<PathBuf>,

    /// Run without TUI (headless mode, prints summary at end).
    #[arg(long)]
    no_tui: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::sink)
        .init();

    let args = Args::parse();


    if args.list_interfaces {
        let devices = capture::list_interfaces()?;
        println!("Available network interfaces:");
        for dev in devices {
            let desc = dev.desc.as_deref().unwrap_or("(no description)");
            println!("  {} — {}", dev.name, desc);
        }
        return Ok(());
    }


    if args.interface.is_none() && args.replay.is_none() {
        anyhow::bail!(
            "Specify either --interface for live capture or --replay for PCAP file replay.\n\
             Use --list-interfaces to see available interfaces."
        );
    }

    let is_replay = args.replay.is_some();


    let inference_config = InferenceConfig {
        base_url: args.inference_url.clone(),
        ..Default::default()
    };
    let inference_client = InferenceClient::new(inference_config)?;


    info!("Checking inference sidecar at {}...", args.inference_url);
    match inference_client.health_check().await {
        Ok(true) => info!("Inference sidecar is healthy"),
        Ok(false) => warn!("Inference sidecar returned unhealthy — predictions will fail"),
        Err(e) => warn!("Cannot reach inference sidecar: {} — predictions will fail", e),
    }


    let flow_table: FlowTable = Arc::new(dashmap::DashMap::new());
    let capture_stats = Arc::new(CaptureStats::default());
    let tui_state = Arc::new(Mutex::new(TuiState::new(is_replay)));


    let (shutdown_tx, shutdown_rx) = watch::channel(false);


    let (flow_tx, flow_rx) = mpsc::channel::<FinalizedFlow>(256);

    let export_csv_path = args.export_csv.clone();
    let classify_handle = {
        let inference_client = inference_client.clone();
        let tui_state = Arc::clone(&tui_state);
        tokio::spawn(async move {
            if let Some(csv_path) = export_csv_path {
                run_csv_pipeline(flow_rx, csv_path).await;
            } else {
                run_classification_pipeline(flow_rx, inference_client, tui_state).await;
            }
        })
    };


    let reaper_config = ReaperConfig {
        idle_timeout: args.idle_timeout,
        min_pkts: args.min_pkts,
        ..Default::default()
    };
    let reaper_handle = {
        let flow_table = Arc::clone(&flow_table);
        let reaper_config = reaper_config.clone();
        let flow_tx = flow_tx.clone();
        let shutdown_rx = shutdown_rx.clone();
        tokio::spawn(async move {
            reaper::run_reaper(flow_table, reaper_config, flow_tx, shutdown_rx).await;
        })
    };


    let _capture_handle = {
        let flow_table = Arc::clone(&flow_table);
        let capture_stats = Arc::clone(&capture_stats);
        let flow_tx_capture = flow_tx.clone();
        let min_pkts = args.min_pkts;
        let shutdown_rx = shutdown_rx.clone();

        if let Some(replay_files) = args.replay {

            let tui_state = Arc::clone(&tui_state);
            let reaper_config = reaper_config.clone();
            tokio::task::spawn_blocking(move || {
                let rt = tokio::runtime::Handle::current();

                for path in &replay_files {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                    info!(file = %path.display(), "Replaying PCAP");
                    match capture::open_offline(path) {
                        Ok(mut cap) => {
                            let flow_tx1 = flow_tx_capture.clone();
                            let flow_tx2 = flow_tx_capture.clone();
                            capture::process_packets(
                                &mut cap,
                                &flow_table,
                                &capture_stats,
                                &mut |old_flow| {
                                    let flow_tx = flow_tx1.clone();
                                    rt.block_on(async {
                                        reaper::emit_restarted_flow(old_flow, min_pkts, &flow_tx)
                                            .await;
                                    });
                                },
                                &mut |early_flow| {
                                    let flow_tx = flow_tx2.clone();
                                    rt.block_on(async {
                                        let _ = flow_tx.send(FinalizedFlow {
                                            flow: early_flow,
                                            reason: reaper::FinalizationReason::EarlyEvaluation,
                                        }).await;
                                    });
                                },
                            );
                        }
                        Err(e) => {
                            error!(file = %path.display(), error = %e, "Failed to open PCAP");
                        }
                    }
                }


                info!("PCAP replay capture complete — finalizing {} remaining flows", flow_table.len());
                rt.block_on(async {
                    reaper::reap_all(&flow_table, &reaper_config, &flow_tx_capture).await;
                });


                drop(flow_tx_capture);


                std::thread::sleep(std::time::Duration::from_millis(500));

                info!("PCAP replay complete");
                tui_state.lock().unwrap().replay_done = true;
            })
        } else {

            let interface = args.interface.unwrap();
            let bpf_filter = args.bpf_filter.clone();
            tokio::task::spawn_blocking(move || {
                match capture::open_live(&interface, &bpf_filter) {
                    Ok(mut cap) => {
                        let rt = tokio::runtime::Handle::current();
                        let flow_tx1 = flow_tx_capture.clone();
                        let flow_tx2 = flow_tx_capture.clone();
                        loop {
                            if *shutdown_rx.borrow() {
                                break;
                            }
                            capture::process_packets(
                                &mut cap,
                                &flow_table,
                                &capture_stats,
                                &mut |old_flow| {
                                    let flow_tx = flow_tx1.clone();
                                    rt.block_on(async {
                                        reaper::emit_restarted_flow(old_flow, min_pkts, &flow_tx)
                                            .await;
                                    });
                                },
                                &mut |early_flow| {
                                    let flow_tx = flow_tx2.clone();
                                    rt.block_on(async {
                                        let _ = flow_tx.send(FinalizedFlow {
                                            flow: early_flow,
                                            reason: reaper::FinalizationReason::EarlyEvaluation,
                                        }).await;
                                    });
                                },
                            );
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "Failed to open live capture");
                    }
                }
            })
        }
    };

    drop(flow_tx);

    if args.no_tui {
        if is_replay {

            loop {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                let done = tui_state.lock().unwrap().replay_done;
                if done {
                    break;
                }
            }

            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        } else {

            tokio::signal::ctrl_c().await?;
        }
        let _ = shutdown_tx.send(true);
    } else {

        let tui_shutdown_tx = shutdown_tx.clone();
        let tui_tui_state = Arc::clone(&tui_state);
        let tui_capture_stats = Arc::clone(&capture_stats);


        let tui_result = tokio::task::spawn_blocking(move || {
            tui::run_tui(tui_tui_state, tui_capture_stats, tui_shutdown_tx)
        })
        .await?;


        let _ = shutdown_tx.send(true);


        tui_result?;
    }


    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let _ = reaper_handle.await;
        let _ = classify_handle.await;
    })
    .await;


    let state = tui_state.lock().unwrap();
    let elapsed = state.start_time.elapsed();
    let elapsed_secs = elapsed.as_secs_f64();
    let pkts = capture_stats.packets_matched();
    let throughput = if elapsed_secs > 0.0 { pkts as f64 / elapsed_secs } else { 0.0 };

    let p50 = state.latency_percentile(50.0).as_secs_f64() * 1000.0;
    let p95 = state.latency_percentile(95.0).as_secs_f64() * 1000.0;
    let p99 = state.latency_percentile(99.0).as_secs_f64() * 1000.0;

    println!("\n╔══════════════════════════════════════╗");
    println!("║        Session Summary               ║");
    println!("╠══════════════════════════════════════╣");
    println!("║  Duration:          {:>12.2}s  ║", elapsed_secs);
    println!("║  Throughput:        {:>10.0} p/s  ║", throughput);
    println!("║  Packets captured:  {:>15}  ║", pkts);
    println!("║  Flows classified:  {:>15}  ║", state.total_mcp + state.total_noise);
    println!("║  MCP detected:      {:>15}  ║", state.total_mcp);
    println!("║  Noise detected:    {:>15}  ║", state.total_noise);
    if let Some(acc) = state.accuracy() {
        println!("║  Accuracy (GT):     {:>14.1}%  ║", acc);
    }
    println!("╠══════════════════════════════════════╣");
    println!("║  Inference p50:     {:>12.2}ms  ║", p50);
    println!("║  Inference p95:     {:>12.2}ms  ║", p95);
    println!("║  Inference p99:     {:>12.2}ms  ║", p99);
    println!("╚══════════════════════════════════════╝");

    Ok(())
}

/// Classification pipeline task.
async fn run_classification_pipeline(
    mut rx: mpsc::Receiver<FinalizedFlow>,
    client: InferenceClient,
    tui_state: Arc<Mutex<TuiState>>,
) {
    let udp_socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => Some(s),
        Err(e) => {
            warn!("Failed to bind UDP socket for proxy control: {}", e);
            None
        }
    };
    let proxy_addr = "127.0.0.1:9999";

    while let Some(finalized) = rx.recv().await {
        let flow = finalized.flow;


        let features = match extract_features(&flow) {
            Some(f) => f,
            None => continue,
        };


        match client.predict(&features).await {
            Ok((prediction, latency)) => {
                let classified = ClassifiedFlow {
                    flow_display: flow.key.display(),
                    label: prediction.label,
                    proba_mcp: prediction.proba[1],
                    proba_noise: prediction.proba[0],
                    pkt_count: flow.pkt_count(),
                    duration_s: flow.end_ts - flow.start_ts,
                    ground_truth: flow.ground_truth_label(),
                    inference_latency: latency,
                    classified_at: Instant::now(),
                    is_closed: !matches!(finalized.reason, reaper::FinalizationReason::EarlyEvaluation),
                };

                if prediction.label == 0 {
                    if let Some(ref sock) = udp_socket {
                        let kill_cmd = format!("KILL {}:{}", flow.key.src_ip, flow.key.src_port);
                        if let Err(e) = sock.send_to(kill_cmd.as_bytes(), proxy_addr).await {
                            warn!("Failed to send KILL command to proxy: {}", e);
                        } else {
                            info!("Sent mid-stream KILL for flow {}", flow.key.display());
                        }
                    }
                }

                tui_state.lock().unwrap().add_flow(classified);
            }
            Err(e) => {
                warn!(
                    flow = %flow.key.display(),
                    error = %e,
                    "Inference failed"
                );
            }
        }
    }
}

use live_analyzer::features::FEATURE_NAMES;

async fn run_csv_pipeline(mut rx: mpsc::Receiver<FinalizedFlow>, csv_path: PathBuf) {
    use std::io::Write;
    let mut file = match std::fs::File::create(&csv_path) {
        Ok(f) => f,
        Err(e) => {
            error!(error = %e, "Failed to create CSV file");
            return;
        }
    };
    
    // Write header — start_ts is included as a session identifier for train/test splitting.
    // Using flow_display + start_ts as the session key is collision-free even with long
    // captures where the OS may reuse ephemeral ports (the previous composite key using
    // seq_iat_01/02 floats was fragile and would collide with more data).
    write!(file, "flow_display,label,start_ts,eval_n,").unwrap();
    write!(file, "{}", FEATURE_NAMES.join(",")).unwrap();
    writeln!(file).unwrap();

    let mut count = 0;
    while let Some(finalized) = rx.recv().await {
        let flow = finalized.flow;
        let eval_n = match finalized.reason {
            reaper::FinalizationReason::EarlyEvaluation => format!("n{}", flow.pkt_count()),
            _ => "final".to_string(),
        };
        let features = match extract_features(&flow) {
            Some(f) => f,
            None => continue,
        };
        let label = flow.ground_truth_label().unwrap_or(255);
        if label == 255 {
            continue; // Skip unknown traffic
        }
        write!(file, "{},{},{},{},", flow.key.display(), label, flow.start_ts, eval_n).unwrap();
        let feat_strs: Vec<String> = features.iter().map(|f| f.to_string()).collect();
        write!(file, "{}", feat_strs.join(",")).unwrap();
        writeln!(file).unwrap();
        count += 1;
    }
    info!("CSV export complete. Wrote {} flows to {}", count, csv_path.display());
}
