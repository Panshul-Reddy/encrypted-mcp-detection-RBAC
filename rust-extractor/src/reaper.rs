//! Flow reaper — periodically sweeps the flow table and finalizes idle flows.
//!
//! A flow is finalized on idle timeout, SYN restart, or shutdown, and then
//! passed to the classification pipeline if it meets the packet threshold.

use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tokio::sync::mpsc;
use tracing::{debug, info};

use crate::flow::{Flow, FlowKey};

/// Configuration for the flow reaper.
#[derive(Debug, Clone)]
pub struct ReaperConfig {
    /// How often to sweep the flow table (seconds).
    pub sweep_interval: Duration,
    /// Flows idle for longer than this are finalized (seconds).
    pub idle_timeout: f64,
    /// Minimum application-layer packets to consider a flow classifiable.
    pub min_pkts: usize,
}

impl Default for ReaperConfig {
    fn default() -> Self {
        Self {
            sweep_interval: Duration::from_secs(5),
            idle_timeout: 30.0,
            min_pkts: 6,
        }
    }
}

/// A finalized flow ready for classification.
#[derive(Debug)]
pub struct FinalizedFlow {
    pub flow: Flow,
    pub reason: FinalizationReason,
}

#[derive(Debug, Clone, Copy)]
pub enum FinalizationReason {
    IdleTimeout,
    SynRestart,
    Shutdown,
    EarlyEvaluation,
}

/// Runs the flow reaper loop. Sends finalized flows to the given channel.
pub async fn run_reaper(
    flow_table: Arc<DashMap<FlowKey, Flow>>,
    config: ReaperConfig,
    tx: mpsc::Sender<FinalizedFlow>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    info!(
        idle_timeout = config.idle_timeout,
        sweep_interval = ?config.sweep_interval,
        min_pkts = config.min_pkts,
        "Flow reaper started"
    );

    let mut interval = tokio::time::interval(config.sweep_interval);

    loop {
        tokio::select! {
            _ = interval.tick() => {
                sweep(&flow_table, &config, &tx).await;
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    info!("Reaper shutting down — finalizing all remaining flows");
                    reap_all(&flow_table, &config, &tx).await;
                    break;
                }
            }
        }
    }
}

/// Sweep the flow table once, removing and emitting idle flows.
async fn sweep(
    flow_table: &DashMap<FlowKey, Flow>,
    config: &ReaperConfig,
    tx: &mpsc::Sender<FinalizedFlow>,
) {

    let now = flow_table
        .iter()
        .map(|entry| entry.value().last_pkt_ts)
        .fold(0.0_f64, f64::max);

    if now == 0.0 {
        return;
    }

    let mut to_remove = Vec::new();

    for entry in flow_table.iter() {
        let idle_time = now - entry.value().last_pkt_ts;
        if idle_time > config.idle_timeout {
            to_remove.push(*entry.key());
        }
    }

    for key in to_remove {
        if let Some((_, flow)) = flow_table.remove(&key) {
            emit_flow(flow, FinalizationReason::IdleTimeout, config.min_pkts, tx).await;
        }
    }
}

/// Finalize ALL remaining flows (used at shutdown or end of replay).
pub async fn reap_all(
    flow_table: &DashMap<FlowKey, Flow>,
    config: &ReaperConfig,
    tx: &mpsc::Sender<FinalizedFlow>,
) {
    let keys: Vec<FlowKey> = flow_table.iter().map(|e| *e.key()).collect();

    for key in keys {
        if let Some((_, flow)) = flow_table.remove(&key) {
            emit_flow(flow, FinalizationReason::Shutdown, config.min_pkts, tx).await;
        }
    }
}

/// Emit a finalized flow if it meets the minimum packet threshold.
async fn emit_flow(
    flow: Flow,
    reason: FinalizationReason,
    min_pkts: usize,
    tx: &mpsc::Sender<FinalizedFlow>,
) {
    if flow.pkt_count() < min_pkts {
        debug!(
            flow = %flow.key.display(),
            pkts = flow.pkt_count(),
            "Dropped flow (below min_pkts threshold)"
        );
        return;
    }

    debug!(
        flow = %flow.key.display(),
        pkts = flow.pkt_count(),
        reason = ?reason,
        "Finalized flow"
    );

    let _ = tx
        .send(FinalizedFlow { flow, reason })
        .await;
}

/// Emit a flow that was evicted by a SYN restart.
pub async fn emit_restarted_flow(
    flow: Flow,
    min_pkts: usize,
    tx: &mpsc::Sender<FinalizedFlow>,
) {
    emit_flow(flow, FinalizationReason::SynRestart, min_pkts, tx).await;
}
