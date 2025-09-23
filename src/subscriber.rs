use std::sync::atomic::Ordering;
use std::thread;
use tracing::{debug, error, info, warn};

use crate::commands::{Command, Response, State};
use crate::state::LOCAL_STATE;
use crate::strategy::FaultStrategy;

// Socket server functions for fault control
pub fn get_current_state() -> State {
    let strategy = LOCAL_STATE.strategy.lock().unwrap();

    State {
        enabled: LOCAL_STATE.enabled.load(Ordering::Relaxed),
        probability: strategy.get_probability().unwrap_or(0),
        strategy: strategy.get_strategy_name().to_string(),
        pattern: strategy.get_pattern().map(|s| s.to_string()),
        error_codes: strategy.get_error_codes().to_vec(),
    }
}

pub fn handle_command(cmd: Command) -> Response {
    match cmd.command.as_str() {
        "toggle" => {
            let current = LOCAL_STATE.enabled.load(Ordering::Relaxed);
            let new_state = !current;
            LOCAL_STATE.enabled.store(new_state, Ordering::Relaxed);
            info!(enabled = new_state, "fault injection toggled");
            Response {
                status: "ok".to_string(),
                message: format!("Fault injection {}", if new_state { "enabled" } else { "disabled" }),
                state: Some(get_current_state()),
            }
        }
        "set_probability" => {
            if let Some(value) = cmd.value {
                if value <= 100 {
                    let mut strategy = LOCAL_STATE.strategy.lock().unwrap();
                    strategy.set_probability(value);
                    info!(probability = value, "probability set");
                    Response {
                        status: "ok".to_string(),
                        message: format!("Probability set to {}%", value),
                        state: Some(get_current_state()),
                    }
                } else {
                    Response {
                        status: "error".to_string(),
                        message: "Invalid probability. Must be 0-100".to_string(),
                        state: None,
                    }
                }
            } else {
                Response {
                    status: "error".to_string(),
                    message: "Missing value parameter".to_string(),
                    state: None,
                }
            }
        }
        "reset" => {
            LOCAL_STATE.enabled.store(false, Ordering::Relaxed);

            // Reset strategy to random with default probability
            let mut strategy = LOCAL_STATE.strategy.lock().unwrap();
            *strategy = FaultStrategy::new_random(25);

            info!("reset to defaults");
            Response {
                status: "ok".to_string(),
                message: "Reset to defaults".to_string(),
                state: Some(get_current_state()),
            }
        }
        "set_strategy" => {
            if let Some(pattern) = cmd.pattern {
                let mut strategy = LOCAL_STATE.strategy.lock().unwrap();
                let error_codes = cmd.error_codes.unwrap_or_default();

                if pattern == "random" {
                    let current_prob = strategy.get_probability().unwrap_or(25);
                    if error_codes.is_empty() {
                        *strategy = FaultStrategy::new_random(current_prob);
                    } else {
                        *strategy = FaultStrategy::new_random_with_codes(current_prob, error_codes);
                    }
                    info!("switched to random fault strategy");
                    Response {
                        status: "ok".to_string(),
                        message: "Strategy set to random".to_string(),
                        state: Some(get_current_state()),
                    }
                } else if !pattern.is_empty() && pattern.chars().all(|c| c == 'X' || c == 'O') {
                    if error_codes.is_empty() {
                        *strategy = FaultStrategy::new_pattern(pattern.clone());
                    } else {
                        *strategy = FaultStrategy::new_pattern_with_codes(pattern.clone(), error_codes);
                    }
                    info!(pattern = %pattern, "switched to pattern fault strategy");
                    Response {
                        status: "ok".to_string(),
                        message: format!("Strategy set to pattern: {}", pattern),
                        state: Some(get_current_state()),
                    }
                } else {
                    Response {
                        status: "error".to_string(),
                        message: "Invalid pattern. Use 'random' or a pattern with only 'X' (fault) and 'O' (pass) characters".to_string(),
                        state: None,
                    }
                }
            } else {
                Response {
                    status: "error".to_string(),
                    message: "Missing pattern parameter".to_string(),
                    state: None,
                }
            }
        }
        "set_error_codes" => {
            if let Some(codes) = cmd.error_codes {
                let error_codes = {
                    let mut strategy = LOCAL_STATE.strategy.lock().unwrap();
                    strategy.set_error_codes(codes);
                    strategy.get_error_codes().to_vec()
                };
                info!(error_codes = ?error_codes, "error codes updated");
                Response {
                    status: "ok".to_string(),
                    message: format!("Error codes set to: {:?}", error_codes),
                    state: Some(get_current_state()),
                }
            } else {
                Response {
                    status: "error".to_string(),
                    message: "Missing error_codes parameter".to_string(),
                    state: None,
                }
            }
        }
        "status" => {
            Response {
                status: "ok".to_string(),
                message: "Current state".to_string(),
                state: Some(get_current_state()),
            }
        }
        _ => {
            Response {
                status: "error".to_string(),
                message: format!("Unknown command: {}", cmd.command),
                state: None,
            }
        }
    }
}

pub fn start_zmq_subscriber() {
    thread::spawn(move || {
        let ctx = zmq::Context::new();
        let subscriber = ctx.socket(zmq::SUB).unwrap();

        // Connect to the broadcast port
        let broadcast_addr = "tcp://127.0.0.1:15559";
        if let Err(e) = subscriber.connect(broadcast_addr) {
            error!(broadcast_addr, error = %e, "failed to connect");
            return;
        }

        // Subscribe to all messages
        subscriber.set_subscribe(b"").unwrap();

        info!(broadcast_addr, pid = std::process::id(), "subscriber listening");

        loop {
            match subscriber.recv_string(0) {
                Ok(Ok(msg)) => {
                    debug!(pid = std::process::id(), message = %msg, "received message");

                    match serde_json::from_str::<Command>(&msg) {
                        Ok(cmd) => {
                            let response = handle_command(cmd);
                            debug!(pid = std::process::id(), response = %response.message, "processed command");
                        }
                        Err(e) => {
                            warn!(error = %e, "invalid JSON");
                        }
                    }
                }
                Ok(Err(e)) => {
                    error!(error = ?e, "UTF-8 decode error");
                }
                Err(e) => {
                    error!(error = %e, "receive error");
                    break;
                }
            }
        }
    });
}