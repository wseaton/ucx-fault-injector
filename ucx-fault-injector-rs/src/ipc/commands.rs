use serde::{Deserialize, Serialize};

// Socket API command and response structures
#[derive(Serialize, Deserialize, Debug)]
pub struct Command {
    pub command: String,
    pub value: Option<f64>,
    pub pattern: Option<String>,
    pub error_codes: Option<Vec<i32>>,
    pub recording_enabled: Option<bool>,
    pub export_format: Option<String>,
    pub hook_name: Option<String>, // for hook-specific enable/disable
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Response {
    pub status: String,
    pub message: String,
    pub state: Option<State>,
    pub recording_data: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct State {
    pub enabled: bool,
    pub probability: f64, // real percentage 0.0-100.0 for display
    pub strategy: String,
    pub pattern: Option<String>,
    pub error_codes: Vec<i32>,
    pub recording_enabled: bool,
    pub total_recorded_calls: u64,
    pub recorded_pattern_length: usize,
    pub hook_config: HookConfig,

    // aggregate statistics
    pub total_calls: u64,
    pub faults_injected: u64,
    pub calls_since_fault: u64,

    // per-function statistics
    pub ucp_get_nbx_calls: u64,
    pub ucp_get_nbx_faults: u64,
    pub ucp_put_nbx_calls: u64,
    pub ucp_put_nbx_faults: u64,
    pub ucp_ep_flush_nbx_calls: u64,
    pub ucp_ep_flush_nbx_faults: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HookConfig {
    pub ucp_get_nbx_enabled: bool,
    pub ucp_put_nbx_enabled: bool,
    pub ucp_ep_flush_nbx_enabled: bool,
}
