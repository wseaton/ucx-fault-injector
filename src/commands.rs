use serde::{Deserialize, Serialize};

// Socket API command and response structures
#[derive(Deserialize, Debug)]
pub struct Command {
    pub command: String,
    pub value: Option<u32>,
    pub pattern: Option<String>,
    pub error_codes: Option<Vec<i32>>,
    pub recording_enabled: Option<bool>,
    pub export_format: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct Response {
    pub status: String,
    pub message: String,
    pub state: Option<State>,
    pub recording_data: Option<serde_json::Value>,
}

#[derive(Serialize, Debug)]
pub struct State {
    pub enabled: bool,
    pub probability: u32,
    pub strategy: String,
    pub pattern: Option<String>,
    pub error_codes: Vec<i32>,
    pub recording_enabled: bool,
    pub total_recorded_calls: u64,
    pub recorded_pattern_length: usize,
}