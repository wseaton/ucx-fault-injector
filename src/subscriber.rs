use std::sync::atomic::Ordering;
use std::thread;
use tracing::{error, info, warn};

use crate::commands::{Command, HookConfig, Response, State};
use crate::recorder::SerializableCallRecord;
use crate::state::LOCAL_STATE;
use crate::strategy::FaultStrategy;

// shared state removed - local state only

// Socket server functions for fault control
pub fn get_current_state() -> State {
    let strategy = LOCAL_STATE.strategy.lock().unwrap();

    let recording_enabled = LOCAL_STATE.call_recorder.is_recording_enabled();
    let total_calls = LOCAL_STATE.call_recorder.get_total_records();
    let pattern_length = LOCAL_STATE.call_recorder.generate_pattern().len();

    let hook_config = LOCAL_STATE.hook_config.lock().unwrap();
    let hook_config_state = HookConfig {
        ucp_get_nbx_enabled: hook_config.ucp_get_nbx_enabled,
        ucp_put_nbx_enabled: hook_config.ucp_put_nbx_enabled,
        ucp_ep_flush_nbx_enabled: hook_config.ucp_ep_flush_nbx_enabled,
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
        hook_config: hook_config_state,

        // aggregate statistics
        total_calls: LOCAL_STATE.total_calls.load(Ordering::Relaxed),
        faults_injected: LOCAL_STATE.faults_injected.load(Ordering::Relaxed),
        calls_since_fault: LOCAL_STATE.calls_since_fault.load(Ordering::Relaxed),

        // per-function statistics
        ucp_get_nbx_calls: LOCAL_STATE.ucp_get_nbx_calls.load(Ordering::Relaxed),
        ucp_get_nbx_faults: LOCAL_STATE.ucp_get_nbx_faults.load(Ordering::Relaxed),
        ucp_put_nbx_calls: LOCAL_STATE.ucp_put_nbx_calls.load(Ordering::Relaxed),
        ucp_put_nbx_faults: LOCAL_STATE.ucp_put_nbx_faults.load(Ordering::Relaxed),
        ucp_ep_flush_nbx_calls: LOCAL_STATE.ucp_ep_flush_nbx_calls.load(Ordering::Relaxed),
        ucp_ep_flush_nbx_faults: LOCAL_STATE.ucp_ep_flush_nbx_faults.load(Ordering::Relaxed),
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
                message: format!(
                    "Fault injection {}",
                    if new_state { "enabled" } else { "disabled" }
                ),
                state: Some(get_current_state()),
                recording_data: None,
            }
        }
        "set_probability" => {
            if let Some(value) = cmd.value {
                if (0.0..=100.0).contains(&value) {
                    let probability_u32 = value as u32;
                    let mut strategy = LOCAL_STATE.strategy.lock().unwrap();
                    strategy.set_probability(probability_u32);
                    drop(strategy);
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
                        message: "Invalid probability. Must be 0.0-100.0".to_string(),
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
                        *strategy =
                            FaultStrategy::new_pattern_with_codes(pattern.clone(), error_codes);
                    }
                    drop(strategy);
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
            if let Some(codes_str) = cmd.pattern {
                // Parse comma-separated error codes from pattern field
                let parsed_codes: Result<Vec<i32>, _> = codes_str
                    .split(',')
                    .map(|s| s.trim().parse::<i32>())
                    .collect();

                match parsed_codes {
                    Ok(codes) => {
                        let error_codes = {
                            let mut strategy = LOCAL_STATE.strategy.lock().unwrap();
                            strategy.set_error_codes(codes);
                            let result = strategy.get_error_codes().to_vec();
                            drop(strategy);
                            result
                        };
                        info!(error_codes = ?error_codes, "error codes updated");
                        Response {
                            status: "ok".to_string(),
                            message: format!("Error codes set to: {:?}", error_codes),
                            state: Some(get_current_state()),
                            recording_data: None,
                        }
                    }
                    Err(_) => {
                        Response {
                            status: "error".to_string(),
                            message: "Invalid error codes format. Use comma-separated integers (e.g., '-3,-6,-20')".to_string(),
                            state: None,
                            recording_data: None,
                        }
                    }
                }
            } else if let Some(codes) = cmd.error_codes {
                // Legacy support for error_codes field
                let error_codes = {
                    let mut strategy = LOCAL_STATE.strategy.lock().unwrap();
                    strategy.set_error_codes(codes);
                    let result = strategy.get_error_codes().to_vec();
                    drop(strategy);
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
                    message: "Missing error codes parameter".to_string(),
                    state: None,
                    recording_data: None,
                }
            }
        }
        "status" => Response {
            status: "ok".to_string(),
            message: "Current state".to_string(),
            state: Some(get_current_state()),
            recording_data: None,
        },
        "stats" => {
            let stats_message = format!(
                "Local Process Statistics (PID {}):\n\
                 - Total calls: {}\n\
                 - Faults injected: {}\n\
                 - Calls since last fault: {}\n\
                 - ucp_get_nbx calls: {}\n\
                 - ucp_get_nbx faults: {}",
                std::process::id(),
                LOCAL_STATE.total_calls.load(Ordering::Relaxed),
                LOCAL_STATE.faults_injected.load(Ordering::Relaxed),
                LOCAL_STATE.calls_since_fault.load(Ordering::Relaxed),
                LOCAL_STATE.ucp_get_nbx_calls.load(Ordering::Relaxed),
                LOCAL_STATE.ucp_get_nbx_faults.load(Ordering::Relaxed),
            );
            Response {
                status: "ok".to_string(),
                message: stats_message,
                state: Some(get_current_state()),
                recording_data: None,
            }
        }
        "toggle_recording" => {
            let current = LOCAL_STATE.call_recorder.is_recording_enabled();
            let new_state = cmd.recording_enabled.unwrap_or(!current);
            LOCAL_STATE.call_recorder.set_recording_enabled(new_state);
            info!(recording_enabled = new_state, "call recording toggled");
            Response {
                status: "ok".to_string(),
                message: format!(
                    "Call recording {}",
                    if new_state { "enabled" } else { "disabled" }
                ),
                state: Some(get_current_state()),
                recording_data: None,
            }
        }
        "clear_recording" => {
            LOCAL_STATE.call_recorder.clear();
            info!("call recording buffer cleared");
            Response {
                status: "ok".to_string(),
                message: "Call recording buffer cleared".to_string(),
                state: Some(get_current_state()),
                recording_data: None,
            }
        }
        "dump_recording" => {
            let format = cmd.export_format.as_deref().unwrap_or("summary");

            let recording_data = match format {
                "pattern" => {
                    let pattern = LOCAL_STATE.call_recorder.generate_pattern();
                    let error_codes = LOCAL_STATE.call_recorder.extract_error_codes();
                    serde_json::json!({
                        "pattern": pattern,
                        "error_codes": error_codes,
                        "total_calls": LOCAL_STATE.call_recorder.get_total_records()
                    })
                }
                "records" => {
                    let count = cmd.value.unwrap_or(100.0) as usize;
                    let records: Vec<SerializableCallRecord> = LOCAL_STATE
                        .call_recorder
                        .get_recent_records(count)
                        .into_iter()
                        .map(SerializableCallRecord::from)
                        .collect();
                    serde_json::json!({
                        "records": records,
                        "total_count": records.len()
                    })
                }
                "summary" => {
                    let summary = LOCAL_STATE.call_recorder.generate_summary();
                    serde_json::to_value(summary).unwrap_or(serde_json::json!({}))
                }
                _ => {
                    let summary = LOCAL_STATE.call_recorder.generate_summary();
                    serde_json::to_value(summary).unwrap_or(serde_json::json!({}))
                }
            };

            // Write to file with PID in filename for unique per-process files
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let pid = std::process::id();
            let filename = format!("ucx-fault-dump-{}-pid{}-{}.json", format, pid, timestamp);

            let file_result = match std::fs::write(
                &filename,
                serde_json::to_string_pretty(&recording_data).unwrap_or_default(),
            ) {
                Ok(()) => format!("Recording data exported to {}", filename),
                Err(e) => format!(
                    "Recording data exported in {} format (file write failed: {})",
                    format, e
                ),
            };

            Response {
                status: "ok".to_string(),
                message: file_result,
                state: Some(get_current_state()),
                recording_data: Some(recording_data),
            }
        }
        "replay_recording" => {
            let pattern = LOCAL_STATE.call_recorder.generate_pattern();
            let error_codes = LOCAL_STATE.call_recorder.extract_error_codes();

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
                *strategy =
                    FaultStrategy::from_recorded_pattern(pattern.clone(), error_codes.clone());
                drop(strategy);

                info!(pattern = %pattern, error_codes = ?error_codes, "replaying recorded pattern");
                Response {
                    status: "ok".to_string(),
                    message: format!(
                        "Replaying recorded pattern: {} ({} calls, {} error codes)",
                        pattern,
                        pattern.len(),
                        error_codes.len()
                    ),
                    state: Some(get_current_state()),
                    recording_data: Some(serde_json::json!({
                        "replayed_pattern": pattern,
                        "error_codes": error_codes
                    })),
                }
            }
        }
        "set_pattern" => {
            if let Some(pattern) = cmd.pattern {
                if !pattern.is_empty() && pattern.chars().all(|c| c == 'X' || c == 'O') {
                    let mut strategy = LOCAL_STATE.strategy.lock().unwrap();
                    strategy.set_pattern(pattern.clone());
                    drop(strategy);
                    info!(pattern = %pattern, "pattern updated");
                    Response {
                        status: "ok".to_string(),
                        message: format!("Pattern set to: {}", pattern),
                        state: Some(get_current_state()),
                        recording_data: None,
                    }
                } else {
                    Response {
                        status: "error".to_string(),
                        message: "Invalid pattern. Use only 'X' (fault) and 'O' (pass) characters"
                            .to_string(),
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
        "enable_hook" => {
            if let Some(hook_name) = cmd.hook_name {
                let mut hook_config = LOCAL_STATE.hook_config.lock().unwrap();
                let result = match hook_name.as_str() {
                    "ucp_get_nbx" => {
                        hook_config.ucp_get_nbx_enabled = true;
                        "ucp_get_nbx hook enabled"
                    }
                    "ucp_put_nbx" => {
                        hook_config.ucp_put_nbx_enabled = true;
                        "ucp_put_nbx hook enabled"
                    }
                    "ucp_ep_flush_nbx" => {
                        hook_config.ucp_ep_flush_nbx_enabled = true;
                        "ucp_ep_flush_nbx hook enabled"
                    }
                    "all" => {
                        hook_config.ucp_get_nbx_enabled = true;
                        hook_config.ucp_put_nbx_enabled = true;
                        hook_config.ucp_ep_flush_nbx_enabled = true;
                        "all hooks enabled"
                    }
                    _ => {
                        return Response {
                            status: "error".to_string(),
                            message: format!("Unknown hook name: {}. Valid options: ucp_get_nbx, ucp_put_nbx, ucp_ep_flush_nbx, all", hook_name),
                            state: None,
                            recording_data: None,
                        };
                    }
                };
                info!(hook_name = hook_name, "hook enabled");
                Response {
                    status: "ok".to_string(),
                    message: result.to_string(),
                    state: Some(get_current_state()),
                    recording_data: None,
                }
            } else {
                Response {
                    status: "error".to_string(),
                    message: "Missing hook_name parameter".to_string(),
                    state: None,
                    recording_data: None,
                }
            }
        }
        "disable_hook" => {
            if let Some(hook_name) = cmd.hook_name {
                let mut hook_config = LOCAL_STATE.hook_config.lock().unwrap();
                let result = match hook_name.as_str() {
                    "ucp_get_nbx" => {
                        hook_config.ucp_get_nbx_enabled = false;
                        "ucp_get_nbx hook disabled"
                    }
                    "ucp_put_nbx" => {
                        hook_config.ucp_put_nbx_enabled = false;
                        "ucp_put_nbx hook disabled"
                    }
                    "ucp_ep_flush_nbx" => {
                        hook_config.ucp_ep_flush_nbx_enabled = false;
                        "ucp_ep_flush_nbx hook disabled"
                    }
                    "all" => {
                        hook_config.ucp_get_nbx_enabled = false;
                        hook_config.ucp_put_nbx_enabled = false;
                        hook_config.ucp_ep_flush_nbx_enabled = false;
                        "all hooks disabled"
                    }
                    _ => {
                        return Response {
                            status: "error".to_string(),
                            message: format!("Unknown hook name: {}. Valid options: ucp_get_nbx, ucp_put_nbx, ucp_ep_flush_nbx, all", hook_name),
                            state: None,
                            recording_data: None,
                        };
                    }
                };
                info!(hook_name = hook_name, "hook disabled");
                Response {
                    status: "ok".to_string(),
                    message: result.to_string(),
                    state: Some(get_current_state()),
                    recording_data: None,
                }
            } else {
                Response {
                    status: "error".to_string(),
                    message: "Missing hook_name parameter".to_string(),
                    state: None,
                    recording_data: None,
                }
            }
        }
        _ => Response {
            status: "error".to_string(),
            message: format!("Unknown command: {}", cmd.command),
            state: None,
            recording_data: None,
        },
    }
}

pub fn start_file_watcher() {
    use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
    use std::path::Path;
    use std::sync::mpsc;

    use std::sync::atomic::AtomicU64;
    use std::time::{SystemTime, UNIX_EPOCH};

    // Track last processed timestamp to avoid duplicates
    static LAST_PROCESSED: AtomicU64 = AtomicU64::new(0);

    thread::spawn(move || {
        let command_file = "/tmp/ucx-fault-commands";
        let command_path = Path::new(command_file);

        // Create parent directory if it doesn't exist
        if let Some(parent) = command_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }

        // Create empty file if it doesn't exist
        if !command_path.exists() {
            std::fs::write(command_file, "").ok();
        }

        // Initialize LAST_PROCESSED to current time to avoid processing old commands
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        LAST_PROCESSED.store(current_time, std::sync::atomic::Ordering::Relaxed);
        info!(
            pid = std::process::id(),
            start_time = current_time,
            "initialized file watcher to only process new commands"
        );

        // Set up file watcher
        let (tx, rx) = mpsc::channel();
        let mut watcher = match RecommendedWatcher::new(tx, Config::default()) {
            Ok(w) => w,
            Err(e) => {
                error!(error = %e, "failed to create file watcher");
                return;
            }
        };

        if let Err(e) = watcher.watch(command_path, RecursiveMode::NonRecursive) {
            error!(command_file, error = %e, "failed to watch command file");
            return;
        }

        info!(
            command_file,
            pid = std::process::id(),
            "file watcher started"
        );

        // Skip processing initial file content to avoid replaying old commands

        // Watch for file changes
        for res in rx {
            match res {
                Ok(Event {
                    kind: EventKind::Modify(_),
                    ..
                }) => {
                    process_command_file(command_file, &LAST_PROCESSED);
                }
                Ok(_) => {} // Ignore other events
                Err(e) => {
                    error!(error = %e, "file watch error");
                }
            }
        }
    });
}

fn process_command_file(file_path: &str, last_processed: &std::sync::atomic::AtomicU64) {
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use std::sync::atomic::Ordering;

    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(_) => return, // File doesn't exist or can't be read
    };

    let reader = BufReader::new(file);
    let current_last = last_processed.load(Ordering::Relaxed);
    let mut new_last = current_last;

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l.trim().to_string(),
            Err(_) => continue,
        };

        if line.is_empty() {
            continue;
        }

        // Parse timestamped command
        let parsed: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, line = %line, "failed to parse command line");
                continue;
            }
        };

        let timestamp = match parsed.get("timestamp").and_then(|t| t.as_u64()) {
            Some(ts) => ts,
            None => {
                warn!(line = %line, "command missing timestamp");
                continue;
            }
        };

        // Skip if we've already processed this command
        if timestamp <= current_last {
            continue;
        }

        // Convert to Command struct
        let cmd: Command = match serde_json::from_value(parsed) {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, line = %line, "failed to parse command");
                continue;
            }
        };

        // Process command
        let is_status_cmd = cmd.command == "status" || cmd.command == "stats";
        let response = handle_command(cmd);

        if is_status_cmd {
            info!(pid = std::process::id(), response = %response.message, state = ?response.state, "processed file command");
        } else if let Some(recording_data) = &response.recording_data {
            info!(pid = std::process::id(), response = %response.message, recording_data = %recording_data, "processed file command");
        } else {
            info!(pid = std::process::id(), response = %response.message, "processed file command");
        }

        new_last = timestamp;
    }

    // Update last processed timestamp
    if new_last > current_last {
        last_processed.store(new_last, Ordering::Relaxed);
    }
}

// UDS-based socket server for per-process control
pub fn start_socket_server() {
    use std::io::{BufRead, BufReader, BufWriter, Write};
    use std::os::unix::net::UnixListener;

    thread::spawn(move || {
        let pid = std::process::id();
        let socket_path = format!("/tmp/ucx-fault-{}.sock", pid);

        // Remove stale socket if it exists
        let _ = std::fs::remove_file(&socket_path);

        let listener = match UnixListener::bind(&socket_path) {
            Ok(l) => l,
            Err(e) => {
                error!(socket_path, error = %e, "failed to bind unix socket");
                return;
            }
        };

        info!(socket_path, pid, "UDS socket server started");

        // Cleanup socket on thread exit
        let cleanup_path = socket_path.clone();
        let _cleanup_guard = scopeguard::guard((), move |_| {
            let _ = std::fs::remove_file(&cleanup_path);
        });

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    // set timeouts to prevent hanging on slow/stuck clients
                    let timeout = std::time::Duration::from_secs(5);
                    if let Err(e) = stream.set_read_timeout(Some(timeout)) {
                        warn!(error = %e, "failed to set read timeout");
                        continue;
                    }
                    if let Err(e) = stream.set_write_timeout(Some(timeout)) {
                        warn!(error = %e, "failed to set write timeout");
                        continue;
                    }

                    let mut reader = BufReader::new(&stream);
                    let mut writer = BufWriter::new(&stream);

                    // Read line-delimited JSON command from stream
                    let mut line = String::new();
                    if let Err(e) = reader.read_line(&mut line) {
                        warn!(error = %e, "failed to read line from socket");
                        continue;
                    }

                    let cmd: Command = match serde_json::from_str(&line) {
                        Ok(c) => c,
                        Err(e) => {
                            warn!(error = %e, line = %line.trim(), "failed to parse command from socket");
                            continue;
                        }
                    };

                    // Process command
                    let is_status_cmd = cmd.command == "status" || cmd.command == "stats";
                    let response = handle_command(cmd);

                    // Send response back with newline delimiter
                    if let Err(e) = serde_json::to_writer(&mut writer, &response) {
                        warn!(error = %e, "failed to write response to socket");
                        continue;
                    }

                    if let Err(e) = writeln!(writer) {
                        warn!(error = %e, "failed to write newline delimiter");
                        continue;
                    }

                    if let Err(e) = writer.flush() {
                        warn!(error = %e, "failed to flush response to socket");
                        continue;
                    }

                    if is_status_cmd {
                        info!(pid, response = %response.message, state = ?response.state, "processed socket command");
                    } else if let Some(recording_data) = &response.recording_data {
                        info!(pid, response = %response.message, recording_data = %recording_data, "processed socket command");
                    } else {
                        info!(pid, response = %response.message, "processed socket command");
                    }
                }
                Err(e) => {
                    error!(error = %e, "failed to accept socket connection");
                }
            }
        }
    });
}
