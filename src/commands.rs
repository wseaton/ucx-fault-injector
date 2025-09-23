use serde::{Deserialize, Serialize};

// Socket API command and response structures
#[derive(Deserialize, Debug)]
pub struct Command {
    pub command: String,
    pub value: Option<u32>,
    pub pattern: Option<String>,
    pub error_codes: Option<Vec<i32>>,
}

#[derive(Serialize, Debug)]
pub struct Response {
    pub status: String,
    pub message: String,
    pub state: Option<State>,
}

#[derive(Serialize, Debug)]
pub struct State {
    pub enabled: bool,
    pub probability: u32,
    pub strategy: String,
    pub pattern: Option<String>,
    pub error_codes: Vec<i32>,
}