use std::sync::atomic::Ordering;
use std::thread;
use tracing::{debug, error, info, warn};

use crate::commands::{Command, Response, State};
use crate::state::LOCAL_STATE;
use crate::shared_state::get_shared_state;
use crate::strategy::FaultStrategy;
use crate::recorder::SerializableCallRecord;

// Helper to sync local state changes to shared memory
fn sync_to_shared_state() {
    if let Some(shared) = get_shared_state() {
        let enabled = LOCAL_STATE.enabled.load(Ordering::Relaxed);
        let strategy = LOCAL_STATE.strategy.lock().unwrap();

        shared.enabled.store(enabled, Ordering::Relaxed);

        match &*strategy {
            FaultStrategy::Random { probability, error_codes } => {
                shared.probability.store(*probability as u32, Ordering::Relaxed);
                shared.strategy_type.store(0, Ordering::Relaxed); // 0 = Random
                shared.pattern_len.store(0, Ordering::Relaxed); // Clear pattern
                shared.set_error_codes(error_codes);
            }
            FaultStrategy::Pattern { pattern, current_position, error_codes } => {
                shared.strategy_type.store(1, Ordering::Relaxed); // 1 = Pattern
                shared.pattern_position.store(*current_position as u64, Ordering::Relaxed);
                shared.set_pattern(pattern);
                shared.set_error_codes(error_codes);
            }
            FaultStrategy::PatternWithMapping { pattern, current_position, error_code_mapping } => {
                shared.strategy_type.store(2, Ordering::Relaxed); // 2 = PatternWithMapping
                shared.pattern_position.store(*current_position as u64, Ordering::Relaxed);
                shared.set_pattern(pattern);
                shared.set_error_codes(error_code_mapping);
            }
        }

        debug!("synchronized local state to shared memory");
    }
}

// Socket server functions for fault control
pub fn get_current_state() -> State {
    let strategy = LOCAL_STATE.strategy.lock().unwrap();

    let (recording_enabled, total_calls, pattern_length) = if let Some(shared) = get_shared_state() {
        (
            shared.call_recorder.is_recording_enabled(),
            shared.call_recorder.get_total_records(),
            shared.call_recorder.generate_pattern().len()
        )
    } else {
        (false, 0, 0)
    };

    State {
        enabled: LOCAL_STATE.enabled.load(Ordering::Relaxed),
        probability: strategy.get_probability().unwrap_or(0),
        strategy: strategy.get_strategy_name().to_string(),
        pattern: strategy.get_pattern().map(|s| s.to_string()),
        error_codes: strategy.get_error_codes().to_vec(),
        recording_enabled,
        total_recorded_calls: total_calls,
        recorded_pattern_length: pattern_length,
    }
}

pub fn handle_command(cmd: Command) -> Response {
    match cmd.command.as_str() {
        "toggle" => {
            let current = LOCAL_STATE.enabled.load(Ordering::Relaxed);
            let new_state = !current;
            LOCAL_STATE.enabled.store(new_state, Ordering::Relaxed);
            sync_to_shared_state();
            info!(enabled = new_state, "fault injection toggled");
            Response {
                status: "ok".to_string(),
                message: format!("Fault injection {}", if new_state { "enabled" } else { "disabled" }),
                state: Some(get_current_state()),
                recording_data: None,
            }
        }
        "set_probability" => {
            if let Some(value) = cmd.value {
                if value <= 100 {
                    let mut strategy = LOCAL_STATE.strategy.lock().unwrap();
                    strategy.set_probability(value);
                    drop(strategy);
                    sync_to_shared_state();
                    info!(probability = value, "probability set");
                    Response {
                        status: "ok".to_string(),
                        message: format!("Probability set to {}%", value),
                        state: Some(get_current_state()),
                        recording_data: None,
                    }
                } else {
                    Response {
                        status: "error".to_string(),
                        message: "Invalid probability. Must be 0-100".to_string(),
                        state: None,
                        recording_data: None,
                    }
                }
            } else {
                Response {
                    status: "error".to_string(),
                    message: "Missing value parameter".to_string(),
                    state: None,
                    recording_data: None,
                }
            }
        }
        "reset" => {
            LOCAL_STATE.enabled.store(false, Ordering::Relaxed);

            // Reset strategy to random with default probability
            let mut strategy = LOCAL_STATE.strategy.lock().unwrap();
            *strategy = FaultStrategy::new_random(25);
            drop(strategy);
            sync_to_shared_state();

            info!("reset to defaults");
            Response {
                status: "ok".to_string(),
                message: "Reset to defaults".to_string(),
                state: Some(get_current_state()),
                recording_data: None,
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
                    drop(strategy);
                    sync_to_shared_state();
                    info!("switched to random fault strategy");
                    Response {
                        status: "ok".to_string(),
                        message: "Strategy set to random".to_string(),
                        state: Some(get_current_state()),
                        recording_data: None,
                    }
                } else if !pattern.is_empty() && pattern.chars().all(|c| c == 'X' || c == 'O') {
                    if error_codes.is_empty() {
                        *strategy = FaultStrategy::new_pattern(pattern.clone());
                    } else {
                        *strategy = FaultStrategy::new_pattern_with_codes(pattern.clone(), error_codes);
                    }
                    drop(strategy);
                    sync_to_shared_state();
                    info!(pattern = %pattern, "switched to pattern fault strategy");
                    Response {
                        status: "ok".to_string(),
                        message: format!("Strategy set to pattern: {}", pattern),
                        state: Some(get_current_state()),
                        recording_data: None,
                    }
                } else {
                    Response {
                        status: "error".to_string(),
                        message: "Invalid pattern. Use 'random' or a pattern with only 'X' (fault) and 'O' (pass) characters".to_string(),
                        state: None,
                        recording_data: None,
                    }
                }
            } else {
                Response {
                    status: "error".to_string(),
                    message: "Missing pattern parameter".to_string(),
                    state: None,
                    recording_data: None,
                }
            }
        }
        "set_error_codes" => {
            if let Some(codes) = cmd.error_codes {
                let error_codes = {
                    let mut strategy = LOCAL_STATE.strategy.lock().unwrap();
                    strategy.set_error_codes(codes);
                    let result = strategy.get_error_codes().to_vec();
                    drop(strategy);
                    sync_to_shared_state();
                    result
                };
                info!(error_codes = ?error_codes, "error codes updated");
                Response {
                    status: "ok".to_string(),
                    message: format!("Error codes set to: {:?}", error_codes),
                    state: Some(get_current_state()),
                    recording_data: None,
                }
            } else {
                Response {
                    status: "error".to_string(),
                    message: "Missing error_codes parameter".to_string(),
                    state: None,
                    recording_data: None,
                }
            }
        }
        "status" => {
            Response {
                status: "ok".to_string(),
                message: "Current state".to_string(),
                state: Some(get_current_state()),
                recording_data: None,
            }
        }
        "stats" => {
            if let Some(shared) = get_shared_state() {
                let stats_message = format!(
                    "Shared Memory Statistics:\n\
                     - Total calls: {}\n\
                     - Faults injected: {}\n\
                     - Calls since last fault: {}\n\
                     - ucp_get_nbx calls: {}\n\
                     - ucp_get_nbx faults: {}\n\
                     - Active processes: {}\n\
                     - Last writer PID: {}\n\
                     - Generation: {}",
                    shared.total_calls.load(Ordering::Relaxed),
                    shared.faults_injected.load(Ordering::Relaxed),
                    shared.calls_since_fault.load(Ordering::Relaxed),
                    shared.ucp_get_nbx_calls.load(Ordering::Relaxed),
                    shared.ucp_get_nbx_faults.load(Ordering::Relaxed),
                    shared.ref_count.load(Ordering::Relaxed),
                    shared.last_writer_pid.load(Ordering::Relaxed),
                    shared.generation.load(Ordering::Relaxed),
                );
                Response {
                    status: "ok".to_string(),
                    message: stats_message,
                    state: Some(get_current_state()),
                    recording_data: None,
                }
            } else {
                Response {
                    status: "error".to_string(),
                    message: "Shared memory not available".to_string(),
                    state: Some(get_current_state()),
                    recording_data: None,
                }
            }
        }
        "toggle_recording" => {
            if let Some(shared) = get_shared_state() {
                let current = shared.call_recorder.is_recording_enabled();
                let new_state = cmd.recording_enabled.unwrap_or(!current);
                shared.call_recorder.set_recording_enabled(new_state);
                info!(recording_enabled = new_state, "call recording toggled");
                Response {
                    status: "ok".to_string(),
                    message: format!("Call recording {}", if new_state { "enabled" } else { "disabled" }),
                    state: Some(get_current_state()),
                    recording_data: None,
                }
            } else {
                Response {
                    status: "error".to_string(),
                    message: "Shared memory not available".to_string(),
                    state: None,
                    recording_data: None,
                }
            }
        }
        "clear_recording" => {
            if let Some(shared) = get_shared_state() {
                shared.call_recorder.clear();
                info!("call recording buffer cleared");
                Response {
                    status: "ok".to_string(),
                    message: "Call recording buffer cleared".to_string(),
                    state: Some(get_current_state()),
                    recording_data: None,
                }
            } else {
                Response {
                    status: "error".to_string(),
                    message: "Shared memory not available".to_string(),
                    state: None,
                    recording_data: None,
                }
            }
        }
        "dump_recording" => {
            if let Some(shared) = get_shared_state() {
                let format = cmd.export_format.as_deref().unwrap_or("summary");

                let recording_data = match format {
                    "pattern" => {
                        let pattern = shared.call_recorder.generate_pattern();
                        let error_codes = shared.call_recorder.extract_error_codes();
                        serde_json::json!({
                            "pattern": pattern,
                            "error_codes": error_codes,
                            "total_calls": shared.call_recorder.get_total_records()
                        })
                    }
                    "records" => {
                        let count = cmd.value.unwrap_or(100) as usize;
                        let records: Vec<SerializableCallRecord> = shared.call_recorder
                            .get_recent_records(count)
                            .into_iter()
                            .map(SerializableCallRecord::from)
                            .collect();
                        serde_json::json!({
                            "records": records,
                            "total_count": records.len()
                        })
                    }
                    "summary" | _ => {
                        let summary = shared.call_recorder.generate_summary();
                        serde_json::to_value(summary).unwrap_or(serde_json::json!({}))
                    }
                };

                Response {
                    status: "ok".to_string(),
                    message: format!("Recording data exported in {} format", format),
                    state: Some(get_current_state()),
                    recording_data: Some(recording_data),
                }
            } else {
                Response {
                    status: "error".to_string(),
                    message: "Shared memory not available".to_string(),
                    state: None,
                    recording_data: None,
                }
            }
        }
        "replay_recording" => {
            if let Some(shared) = get_shared_state() {
                let pattern = shared.call_recorder.generate_pattern();
                let error_codes = shared.call_recorder.extract_error_codes();

                if pattern.is_empty() {
                    Response {
                        status: "error".to_string(),
                        message: "No recorded pattern available for replay".to_string(),
                        state: Some(get_current_state()),
                        recording_data: None,
                    }
                } else {
                    // Create new strategy from recorded pattern
                    let mut strategy = LOCAL_STATE.strategy.lock().unwrap();
                    *strategy = FaultStrategy::from_recorded_pattern(pattern.clone(), error_codes.clone());
                    drop(strategy);
                    sync_to_shared_state();

                    info!(pattern = %pattern, error_codes = ?error_codes, "replaying recorded pattern");
                    Response {
                        status: "ok".to_string(),
                        message: format!("Replaying recorded pattern: {} ({} calls, {} error codes)",
                                       pattern, pattern.len(), error_codes.len()),
                        state: Some(get_current_state()),
                        recording_data: Some(serde_json::json!({
                            "replayed_pattern": pattern,
                            "error_codes": error_codes
                        })),
                    }
                }
            } else {
                Response {
                    status: "error".to_string(),
                    message: "Shared memory not available".to_string(),
                    state: None,
                    recording_data: None,
                }
            }
        }
        _ => {
            Response {
                status: "error".to_string(),
                message: format!("Unknown command: {}", cmd.command),
                state: None,
                recording_data: None,
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
                            let is_status_cmd = cmd.command == "status" || cmd.command == "stats";
                            let response = handle_command(cmd);
                            if is_status_cmd {
                                info!(pid = std::process::id(), response = %response.message, state = ?response.state, "processed command");
                            } else {
                                info!(pid = std::process::id(), response = %response.message, "processed command");
                            }
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