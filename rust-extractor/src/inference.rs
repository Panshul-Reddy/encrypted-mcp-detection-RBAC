//! HTTP client for the Python inference sidecar.
//!
//! Sends feature vectors to `POST /predict` and receives classification results.

use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use tracing::{debug, warn};

/// Inference client configuration.
#[derive(Debug, Clone)]
pub struct InferenceConfig {
    /// Base URL of the inference sidecar (e.g., "http://localhost:5000").
    pub base_url: String,
    /// HTTP request timeout.
    pub timeout: Duration,
}

impl Default for InferenceConfig {
    fn default() -> Self {
        Self {
            base_url: "http://localhost:5000".to_string(),
            timeout: Duration::from_secs(5),
        }
    }
}

#[derive(Debug, Serialize)]
struct PredictRequest {
    features: Vec<f64>,
    source_ip: String,
    src_port: u16,
    dst_ip: String,
    dst_port: u16,
}

#[derive(Debug, Serialize)]
struct PredictBatchRequest {
    batch: Vec<PredictRequest>,
}

/// Single classification response.
#[derive(Debug, Clone, Deserialize)]
pub struct PredictResponse {
    pub label: u8,
    pub proba: [f64; 2],
    pub rbac_decision: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PredictBatchResponse {
    predictions: Vec<PredictResponse>,
}

/// HTTP client for the inference sidecar.
#[derive(Debug, Clone)]
pub struct InferenceClient {
    client: Client,
    config: InferenceConfig,
}

impl InferenceClient {
    pub fn new(config: InferenceConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(config.timeout)
            .pool_max_idle_per_host(4)
            .build()
            .context("Failed to build HTTP client")?;

        Ok(Self { client, config })
    }

    /// Check if the inference server is healthy.
    pub async fn health_check(&self) -> Result<bool> {
        let url = format!("{}/health", self.config.base_url);
        match self.client.get(&url).send().await {
            Ok(resp) => Ok(resp.status().is_success()),
            Err(e) => {
                warn!("Health check failed: {}", e);
                Ok(false)
            }
        }
    }

    /// Classify a single flow's feature vector.
    pub async fn predict(
        &self,
        features: &[f64; 115],
        source_ip: &str,
        src_port: u16,
        dst_ip: &str,
        dst_port: u16,
    ) -> Result<(PredictResponse, Duration)> {
        let url = format!("{}/predict", self.config.base_url);
        let body = PredictRequest {
            features: features.to_vec(),
            source_ip: source_ip.to_string(),
            src_port,
            dst_ip: dst_ip.to_string(),
            dst_port,
        };

        let start = Instant::now();
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .context("Inference request failed")?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("Inference returned {}: {}", status, text);
        }

        let prediction: PredictResponse = resp
            .json()
            .await
            .context("Failed to parse inference response")?;
        let latency = start.elapsed();

        debug!(
            label = prediction.label,
            proba_mcp = prediction.proba[1],
            latency_ms = latency.as_millis(),
            "Prediction received"
        );

        Ok((prediction, latency))
    }

    /// Classify a batch of feature vectors.
    pub async fn predict_batch(
        &self,
        batch: &[(&[f64; 115], &str, u16, &str, u16)],
    ) -> Result<(Vec<PredictResponse>, Duration)> {
        let url = format!("{}/predict_batch", self.config.base_url);
        let body = PredictBatchRequest {
            batch: batch
                .iter()
                .map(|(f, src_ip, src_port, dst_ip, dst_port)| PredictRequest {
                    features: f.to_vec(),
                    source_ip: src_ip.to_string(),
                    src_port: *src_port,
                    dst_ip: dst_ip.to_string(),
                    dst_port: *dst_port,
                })
                .collect(),
        };

        let start = Instant::now();
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .context("Batch inference request failed")?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("Batch inference returned {}: {}", status, text);
        }

        let batch_resp: PredictBatchResponse = resp
            .json()
            .await
            .context("Failed to parse batch inference response")?;
        let latency = start.elapsed();

        Ok((batch_resp.predictions, latency))
    }
}
