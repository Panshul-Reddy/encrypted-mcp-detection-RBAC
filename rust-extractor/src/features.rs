//! Feature extraction — computes the 105 features expected by the unified model.
use crate::flow::{Direction, Flow};

pub const FEATURE_NAMES: [&str; 105] = [
    // Base 16 features
    "duration_s",
    "total_pkts",
    "total_bytes",
    "pkts_up",
    "mean_pkt_sz",
    "std_pkt_sz",
    "min_pkt_sz",
    "max_pkt_sz",
    "mean_pkt_sz_up",
    "std_iat",
    "mean_iat_up",
    "std_iat_up",
    "std_iat_down",
    "byte_ratio_up",
    "pkt_ratio_up",
    "entropy",

    // 20 Sequence Size features
    "seq_size_00", "seq_size_01", "seq_size_02", "seq_size_03", "seq_size_04",
    "seq_size_05", "seq_size_06", "seq_size_07", "seq_size_08", "seq_size_09",
    "seq_size_10", "seq_size_11", "seq_size_12", "seq_size_13", "seq_size_14",
    "seq_size_15", "seq_size_16", "seq_size_17", "seq_size_18", "seq_size_19",

    // 20 Sequence Direction features (+1 up, -1 down)
    "seq_dir_00", "seq_dir_01", "seq_dir_02", "seq_dir_03", "seq_dir_04",
    "seq_dir_05", "seq_dir_06", "seq_dir_07", "seq_dir_08", "seq_dir_09",
    "seq_dir_10", "seq_dir_11", "seq_dir_12", "seq_dir_13", "seq_dir_14",
    "seq_dir_15", "seq_dir_16", "seq_dir_17", "seq_dir_18", "seq_dir_19",

    // 20 Sequence IAT features
    "seq_iat_00", "seq_iat_01", "seq_iat_02", "seq_iat_03", "seq_iat_04",
    "seq_iat_05", "seq_iat_06", "seq_iat_07", "seq_iat_08", "seq_iat_09",
    "seq_iat_10", "seq_iat_11", "seq_iat_12", "seq_iat_13", "seq_iat_14",
    "seq_iat_15", "seq_iat_16", "seq_iat_17", "seq_iat_18", "seq_iat_19",

    // 17 TLS UP features
    "tls_up_03", "tls_up_04", "tls_up_05", "tls_up_06", "tls_up_07",
    "tls_up_08", "tls_up_09", "tls_up_10", "tls_up_11", "tls_up_12",
    "tls_up_13", "tls_up_14", "tls_up_15", "tls_up_16", "tls_up_17",
    "tls_up_18", "tls_up_19",

    // 12 TLS DOWN features
    "tls_down_08", "tls_down_09", "tls_down_10", "tls_down_11", "tls_down_12",
    "tls_down_13", "tls_down_14", "tls_down_15", "tls_down_16", "tls_down_17",
    "tls_down_18", "tls_down_19",
];

pub fn extract_features(flow: &Flow) -> Option<[f64; 105]> {
    if flow.pkts.is_empty() {
        return None;
    }

    let mut features = [0.0_f64; 105];
    let mut idx = 0;

    let mut sizes_all: Vec<f64> = Vec::with_capacity(flow.pkts.len());
    let mut sizes_up: Vec<f64> = Vec::new();
    let mut times_all: Vec<f64> = Vec::with_capacity(flow.pkts.len());
    let mut times_up: Vec<f64> = Vec::new();
    let mut times_down: Vec<f64> = Vec::new();

    for pkt in &flow.pkts {
        let sz = pkt.payload_len as f64;
        sizes_all.push(sz);
        times_all.push(pkt.ts);

        match pkt.direction {
            Direction::Up => {
                sizes_up.push(sz);
                times_up.push(pkt.ts);
            }
            Direction::Down => {
                times_down.push(pkt.ts);
            }
        }
    }

    let total_bytes: f64 = sizes_all.iter().sum();
    let bytes_up: f64 = sizes_up.iter().sum();

    let iats_all = inter_arrivals(&times_all);
    let iats_up = inter_arrivals(&times_up);
    let iats_down = inter_arrivals(&times_down);

    // Base features
    features[idx] = flow.end_ts - flow.start_ts; idx += 1;
    features[idx] = flow.pkts.len() as f64; idx += 1;
    features[idx] = total_bytes; idx += 1;
    features[idx] = sizes_up.len() as f64; idx += 1;
    features[idx] = safe_mean(&sizes_all); idx += 1;
    features[idx] = safe_std(&sizes_all); idx += 1;
    
    let min_sz = sizes_all.iter().copied().fold(f64::INFINITY, f64::min);
    features[idx] = if min_sz.is_infinite() { 0.0 } else { min_sz }; idx += 1;
    
    let max_sz = sizes_all.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    features[idx] = if max_sz.is_infinite() { 0.0 } else { max_sz }; idx += 1;

    features[idx] = safe_mean(&sizes_up); idx += 1;
    features[idx] = safe_std(&iats_all); idx += 1;
    features[idx] = safe_mean(&iats_up); idx += 1;
    features[idx] = safe_std(&iats_up); idx += 1;
    features[idx] = safe_std(&iats_down); idx += 1;
    features[idx] = if total_bytes > 0.0 { bytes_up / total_bytes } else { 0.0 }; idx += 1;
    features[idx] = if !flow.pkts.is_empty() { sizes_up.len() as f64 / flow.pkts.len() as f64 } else { 0.0 }; idx += 1;
    features[idx] = flow.first_payload_entropy; idx += 1;

    // 20 Sequence Size features
    for i in 0..20 {
        features[idx] = sizes_all.get(i).copied().unwrap_or(0.0);
        idx += 1;
    }

    // 20 Sequence Direction features
    for i in 0..20 {
        features[idx] = if let Some(pkt) = flow.pkts.get(i) {
            match pkt.direction {
                Direction::Up => 1.0,
                Direction::Down => -1.0,
            }
        } else {
            0.0
        };
        idx += 1;
    }

    // 20 Sequence IAT features
    features[idx] = 0.0; // iat_00 is always 0
    idx += 1;
    for i in 1..20 {
        features[idx] = iats_all.get(i - 1).copied().unwrap_or(0.0);
        idx += 1;
    }

    // 17 TLS UP features
    for i in 3..20 {
        features[idx] = flow.tls_appdata_up.get(i).map(|&v| v as f64).unwrap_or(0.0);
        idx += 1;
    }

    // 12 TLS DOWN features
    for i in 8..20 {
        features[idx] = flow.tls_appdata_down.get(i).map(|&v| v as f64).unwrap_or(0.0);
        idx += 1;
    }

    debug_assert_eq!(idx, 105);
    Some(features)
}

fn safe_mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.iter().sum::<f64>() / values.len() as f64
}

fn safe_std(values: &[f64]) -> f64 {
    if values.len() < 2 {
        return 0.0;
    }
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (values.len() - 1) as f64;
    variance.sqrt()
}

fn inter_arrivals(times: &[f64]) -> Vec<f64> {
    if times.len() < 2 {
        return Vec::new();
    }
    times.windows(2).map(|w| w[1] - w[0]).collect()
}
