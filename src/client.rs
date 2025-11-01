#![allow(dead_code)]

use clap::{Parser, Subcommand};
use comfy_table::{Cell, Table};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

// version info from build-time git metadata (similar to setuptools_scm)
fn version_info() -> String {
    let cargo_version = env!("CARGO_PKG_VERSION");
    let git_sha = env!("VERGEN_GIT_SHA");
    let git_dirty = env!("VERGEN_GIT_DIRTY");

    if git_dirty == "true" {
        format!("{}-dev+{}.dirty", cargo_version, &git_sha[..7])
    } else {
        format!("{}-dev+{}", cargo_version, &git_sha[..7])
    }
}

fn validate_probability(s: &str) -> Result<f64, String> {
    let value: f64 = s
        .parse()
        .map_err(|_| format!("'{}' is not a valid number", s))?;

    if !(0.0..=100.0).contains(&value) {
        return Err(format!(
            "probability must be between 0.0 and 100.0, got {}",
            value
        ));
    }

    Ok(value)
}

// IPC backend selection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpcBackend {
    Socket, // Unix domain socket (default)
    File,   // File-based watching (legacy)
}

impl IpcBackend {
    fn from_env() -> Self {
        match std::env::var("UCX_FAULT_IPC_BACKEND").as_deref() {
            Ok("file") => IpcBackend::File,
            Ok("socket") => IpcBackend::Socket,
            _ => IpcBackend::Socket, // default to socket
        }
    }
}

// Response structure from server (mirrors commands::Response)
#[derive(Deserialize, Debug)]
struct Response {
    status: String,
    message: String,
    state: Option<State>,
    recording_data: Option<serde_json::Value>,
}

#[derive(Deserialize, Debug)]
struct State {
    enabled: bool,
    probability: u32,
    strategy: String,
    pattern: Option<String>,
    error_codes: Vec<i32>,
    recording_enabled: bool,
    total_recorded_calls: u64,
    recorded_pattern_length: usize,
    hook_config: HookConfig,
    total_calls: u64,
    faults_injected: u64,
    calls_since_fault: u64,
    ucp_get_nbx_calls: u64,
    ucp_get_nbx_faults: u64,
    ucp_put_nbx_calls: u64,
    ucp_put_nbx_faults: u64,
    ucp_ep_flush_nbx_calls: u64,
    ucp_ep_flush_nbx_faults: u64,
}

#[derive(Deserialize, Debug)]
struct HookConfig {
    ucp_get_nbx_enabled: bool,
    ucp_put_nbx_enabled: bool,
    ucp_ep_flush_nbx_enabled: bool,
}

#[derive(Serialize, Clone)]
struct Command {
    command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    scenario: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recording_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    export_format: Option<String>,
}

#[derive(Parser)]
#[command(name = "ucx-fault-client")]
#[command(about = "UCX Fault Injector Client (ZMQ Broadcast)")]
#[command(long_about = "A client for controlling fault injection in UCX applications")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Toggle fault injection on/off
    Toggle,
    /// Set fault injection probability (0.0-100.0)
    Probability {
        /// Probability percentage (0.0-100.0)
        #[arg(value_parser = validate_probability)]
        probability: f64,
    },
    /// Set error codes for fault injection
    ErrorCodes {
        /// Comma-separated list of error codes (use -- for negative values: "-- -3,-6,-20")
        codes: String,
    },
    /// Set fault pattern for deterministic injection
    Pattern {
        /// Pattern like 'XOOOOXOO' where X=fault, O=pass
        pattern: String,
    },
    /// Reset to default settings
    Reset,
    /// Show current state (broadcasts only)
    Status,
    /// Toggle call recording on/off
    RecordToggle {
        /// Enable or disable recording (optional - toggles if not specified)
        #[arg(value_parser = clap::value_parser!(bool))]
        enabled: Option<bool>,
    },
    /// Clear recorded call buffer
    RecordClear,
    /// Dump recorded calls in specified format
    RecordDump {
        /// Output format
        #[arg(default_value = "summary")]
        #[arg(value_parser = ["summary", "pattern", "records"])]
        format: String,
    },
    /// Dump last N call records (implies 'records' format)
    RecordDumpCount {
        /// Number of records to dump
        count: u32,
    },
    /// Replay recorded fault pattern
    Replay,
    /// Show aggregate statistics across all injected processes
    AggregateStats {
        /// Show detailed per-function breakdown
        #[arg(long)]
        detailed: bool,
        /// Group transfers by size buckets
        #[arg(long)]
        group_by_size: bool,
    },
}

fn send_command_file(command: Command) -> Result<(), Box<dyn std::error::Error>> {
    use nix::fcntl::{Flock, FlockArg};
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    let command_file = "/tmp/ucx-fault-commands";
    let lock_file = "/tmp/ucx-fault-commands.lock";

    // Create lock file for atomic writes
    let lock_fd = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(lock_file)?;

    // Acquire exclusive lock
    let _lock = Flock::lock(lock_fd, FlockArg::LockExclusive)
        .map_err(|e| format!("Failed to acquire lock: {:?}", e))?;

    // Create timestamped command
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let timestamped_command = serde_json::json!({
        "timestamp": timestamp,
        "command": command.command,
        "value": command.value,
        "pattern": command.pattern,
        "recording_enabled": command.recording_enabled,
        "export_format": command.export_format,
        "scenario": command.scenario
    });

    let command_json = serde_json::to_string(&timestamped_command)?;

    // Append command to file
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .append(true)
        .open(command_file)?;

    writeln!(file, "{}", command_json)?;
    file.sync_all()?;

    info!(command_file, command = %command_json, "command written to file");

    Ok(())
}

fn is_process_alive(pid: u32) -> bool {
    std::fs::metadata(format!("/proc/{}", pid)).is_ok()
}

fn send_command_socket(command: Command) -> Result<(), Box<dyn std::error::Error>> {
    use glob::glob;

    // discover all socket files
    let socket_pattern = "/tmp/ucx-fault-*.sock";
    let all_sockets: Vec<_> = glob(socket_pattern)?.filter_map(Result::ok).collect();

    // filter out stale sockets from dead processes
    let mut sockets = Vec::new();
    let mut cleaned_count = 0;

    for socket_path in all_sockets {
        let pid_str = socket_path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|s| s.strip_prefix("ucx-fault-"))
            .and_then(|s| s.strip_suffix(".sock"));

        if let Some(pid_str) = pid_str {
            if let Ok(pid) = pid_str.parse::<u32>() {
                if is_process_alive(pid) {
                    sockets.push(socket_path);
                } else {
                    // clean up stale socket
                    let _ = std::fs::remove_file(&socket_path);
                    cleaned_count += 1;
                }
                continue;
            }
        }
        // keep sockets we can't parse (shouldn't happen)
        sockets.push(socket_path);
    }

    if cleaned_count > 0 {
        info!(count = cleaned_count, "cleaned up stale socket(s)");
    }

    if sockets.is_empty() {
        error!(socket_pattern, "no UCX fault injector processes found");
        return Err("No target processes found".into());
    }

    info!(count = sockets.len(), "found active injected process(es)");

    // run async broadcast in blocking context
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async_broadcast_command(sockets, command))
}

async fn async_broadcast_command(
    sockets: Vec<std::path::PathBuf>,
    command: Command,
) -> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    // spawn parallel tasks for each socket
    let tasks: Vec<_> = sockets
        .into_iter()
        .map(|socket_path| {
            let command = command.clone();
            tokio::spawn(async move {
                // extract PID from socket path
                let pid = socket_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .and_then(|s| s.strip_prefix("ucx-fault-"))
                    .and_then(|s| s.strip_suffix(".sock"))
                    .unwrap_or("unknown")
                    .to_string();

                // connect to socket with timeout
                let stream = match tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    UnixStream::connect(&socket_path),
                )
                .await
                {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        warn!(pid, error = %e, "failed to connect");
                        return Err(format!("connect failed: {}", e));
                    }
                    Err(_) => {
                        warn!(pid, "connection timeout");
                        return Err("connection timeout".to_string());
                    }
                };

                let (reader, mut writer) = stream.into_split();
                let mut reader = BufReader::new(reader);

                // send command with newline delimiter
                let command_json = match serde_json::to_string(&command) {
                    Ok(json) => json,
                    Err(e) => {
                        error!(pid, error = %e, "failed to serialize command");
                        return Err(format!("serialization failed: {}", e));
                    }
                };

                if let Err(e) = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    writer.write_all(format!("{}\n", command_json).as_bytes()),
                )
                .await
                {
                    error!(pid, error = %e, "failed to send command");
                    return Err(format!("write failed: {}", e));
                }

                if let Err(e) = writer.flush().await {
                    error!(pid, error = %e, "failed to flush command");
                    return Err(format!("flush failed: {}", e));
                }

                // read line-delimited JSON response with timeout
                let mut response_line = String::new();
                if let Err(e) = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    reader.read_line(&mut response_line),
                )
                .await
                {
                    error!(pid, error = %e, "failed to read response line");
                    return Err(format!("read timeout: {}", e));
                }

                let response: Response = match serde_json::from_str(&response_line) {
                    Ok(r) => r,
                    Err(e) => {
                        error!(pid, error = %e, line = %response_line.trim(), "failed to parse response");
                        return Err(format!("parse failed: {}", e));
                    }
                };

                info!(pid, status = %response.status, message = %response.message, "command processed");
                Ok(())
            })
        })
        .collect();

    // wait for all tasks to complete
    let results = futures::future::join_all(tasks).await;

    let mut success_count = 0;
    let mut error_count = 0;

    for result in results {
        match result {
            Ok(Ok(())) => success_count += 1,
            Ok(Err(_)) | Err(_) => error_count += 1,
        }
    }

    if error_count > 0 {
        warn!(
            success_count,
            error_count, "command broadcast completed with errors"
        );
        Err(format!("{} process(es) failed to respond", error_count).into())
    } else {
        info!(success_count, "command broadcast completed successfully");
        Ok(())
    }
}

async fn async_collect_stats(
    sockets: Vec<(u32, std::path::PathBuf)>,
) -> Result<std::collections::HashMap<u32, State>, Box<dyn std::error::Error>> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    // spawn parallel tasks for each socket
    let tasks: Vec<_> = sockets
        .into_iter()
        .map(|(pid, socket_path)| {
            tokio::spawn(async move {
                // connect to socket with timeout
                let stream = match tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    UnixStream::connect(&socket_path),
                )
                .await
                {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        warn!(pid, error = %e, "failed to connect, skipping");
                        return None;
                    }
                    Err(_) => {
                        warn!(pid, "connection timeout, skipping");
                        return None;
                    }
                };

                let (reader, mut writer) = stream.into_split();
                let mut reader = BufReader::new(reader);

                // send status command
                let command = Command {
                    command: "status".to_string(),
                    scenario: None,
                    value: None,
                    pattern: None,
                    recording_enabled: None,
                    export_format: None,
                };

                let command_json = match serde_json::to_string(&command) {
                    Ok(json) => json,
                    Err(e) => {
                        warn!(pid, error = %e, "failed to serialize command");
                        return None;
                    }
                };

                if let Err(e) = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    writer.write_all(format!("{}\n", command_json).as_bytes()),
                )
                .await
                {
                    warn!(pid, error = %e, "failed to send command");
                    return None;
                }

                if let Err(e) = writer.flush().await {
                    warn!(pid, error = %e, "failed to flush command");
                    return None;
                }

                // read response with timeout
                let mut response_line = String::new();
                if let Err(e) = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    reader.read_line(&mut response_line),
                )
                .await
                {
                    warn!(pid, error = %e, "failed to read response, skipping");
                    return None;
                }

                let response: Response = match serde_json::from_str(&response_line) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!(pid, error = %e, "failed to parse response, skipping");
                        return None;
                    }
                };

                response.state.map(|state| (pid, state))
            })
        })
        .collect();

    // wait for all tasks to complete
    let results = futures::future::join_all(tasks).await;

    let mut process_stats = std::collections::HashMap::new();
    for result in results {
        if let Ok(Some((pid, state))) = result {
            process_stats.insert(pid, state);
        }
    }

    Ok(process_stats)
}

// aggregate statistics collection and display
fn aggregate_stats(detailed: bool, group_by_size: bool) -> Result<(), Box<dyn std::error::Error>> {
    use glob::glob;

    // discover all socket files
    let socket_pattern = "/tmp/ucx-fault-*.sock";
    let all_sockets: Vec<_> = glob(socket_pattern)?.filter_map(Result::ok).collect();

    // filter out stale sockets
    let mut sockets = Vec::new();
    for socket_path in all_sockets {
        let pid_str = socket_path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|s| s.strip_prefix("ucx-fault-"))
            .and_then(|s| s.strip_suffix(".sock"));

        if let Some(pid_str) = pid_str {
            if let Ok(pid) = pid_str.parse::<u32>() {
                if is_process_alive(pid) {
                    sockets.push((pid, socket_path));
                }
            }
        }
    }

    if sockets.is_empty() {
        error!(socket_pattern, "no UCX fault injector processes found");
        return Err("No target processes found".into());
    }

    info!("");
    info!("═══ UCX FAULT INJECTOR: AGGREGATE STATISTICS ═══");
    info!("");

    // collect stats from all processes in parallel
    let runtime = tokio::runtime::Runtime::new()?;
    let process_stats = runtime.block_on(async_collect_stats(sockets))?;

    if process_stats.is_empty() {
        error!("no statistics collected from any process");
        return Err("Failed to collect stats".into());
    }

    // aggregate totals
    let mut total_calls = 0u64;
    let mut total_faults = 0u64;
    let mut total_get_calls = 0u64;
    let mut total_get_faults = 0u64;
    let mut total_put_calls = 0u64;
    let mut total_put_faults = 0u64;
    let mut total_flush_calls = 0u64;
    let mut total_flush_faults = 0u64;

    for state in process_stats.values() {
        total_calls += state.total_calls;
        total_faults += state.faults_injected;
        total_get_calls += state.ucp_get_nbx_calls;
        total_get_faults += state.ucp_get_nbx_faults;
        total_put_calls += state.ucp_put_nbx_calls;
        total_put_faults += state.ucp_put_nbx_faults;
        total_flush_calls += state.ucp_ep_flush_nbx_calls;
        total_flush_faults += state.ucp_ep_flush_nbx_faults;
    }

    let global_fault_rate = if total_calls > 0 {
        (total_faults as f64 / total_calls as f64) * 100.0
    } else {
        0.0
    };

    // display session overview
    info!("SESSION OVERVIEW");
    info!("Total Processes:        {}", process_stats.len());
    info!("Total Calls (all PIDs): {}", total_calls);
    info!(
        "Total Faults Injected:  {} ({:.2}%)",
        total_faults, global_fault_rate
    );
    info!("");

    // per-process breakdown
    info!("PER-PROCESS BREAKDOWN");
    let mut process_table = Table::new();
    process_table.set_header(vec![
        "PID",
        "Total Calls",
        "Faults",
        "Fault Rate",
        "Recording",
    ]);

    let mut pids: Vec<_> = process_stats.keys().collect();
    pids.sort();

    for pid in pids {
        let state = &process_stats[pid];
        let fault_rate = if state.total_calls > 0 {
            (state.faults_injected as f64 / state.total_calls as f64) * 100.0
        } else {
            0.0
        };
        let recording_status = if state.recording_enabled {
            "enabled"
        } else {
            "disabled"
        };

        process_table.add_row(vec![
            Cell::new(pid),
            Cell::new(state.total_calls),
            Cell::new(state.faults_injected),
            Cell::new(format!("{:.2}%", fault_rate)),
            Cell::new(recording_status),
        ]);
    }
    info!("\n{}", process_table);

    // function-level statistics
    if detailed {
        info!("FUNCTION HOOK STATISTICS");
        let mut func_table = Table::new();
        func_table.set_header(vec![
            "Function",
            "Total Calls",
            "% of Total",
            "Faults",
            "Fault Rate",
        ]);

        let functions = [
            ("ucp_get_nbx", total_get_calls, total_get_faults),
            ("ucp_put_nbx", total_put_calls, total_put_faults),
            ("ucp_ep_flush_nbx", total_flush_calls, total_flush_faults),
        ];

        for (name, calls, faults) in &functions {
            if *calls > 0 {
                let pct_of_total = (*calls as f64 / total_calls as f64) * 100.0;
                let fault_rate = (*faults as f64 / *calls as f64) * 100.0;
                func_table.add_row(vec![
                    Cell::new(name),
                    Cell::new(calls),
                    Cell::new(format!("{:.1}%", pct_of_total)),
                    Cell::new(faults),
                    Cell::new(format!("{:.2}%", fault_rate)),
                ]);
            }
        }
        info!("\n{}", func_table);
    }

    if group_by_size {
        info!("(Parameter grouping analysis coming soon...)");
        info!("");
    }

    Ok(())
}

fn main() {
    // initialize tracing
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .compact()
        .init();

    info!(version = %version_info(), "ucx-fault-client starting");

    let cli = Cli::parse();

    // handle aggregate-stats specially (doesn't broadcast a command)
    if let Commands::AggregateStats {
        detailed,
        group_by_size,
    } = cli.command
    {
        if let Err(e) = aggregate_stats(detailed, group_by_size) {
            error!(error = %e, "failed to collect aggregate statistics");
            std::process::exit(1);
        }
        return;
    }

    let command = match cli.command {
        Commands::Toggle => Command {
            command: "toggle".to_string(),
            scenario: None,
            value: None,
            pattern: None,
            recording_enabled: None,
            export_format: None,
        },
        Commands::Probability { probability } => Command {
            command: "set_probability".to_string(),
            scenario: None,
            value: Some(probability),
            pattern: None,
            recording_enabled: None,
            export_format: None,
        },
        Commands::ErrorCodes { codes } => Command {
            command: "set_error_codes".to_string(),
            scenario: None,
            value: None,
            pattern: Some(codes),
            recording_enabled: None,
            export_format: None,
        },
        Commands::Pattern { pattern } => Command {
            command: "set_pattern".to_string(),
            scenario: None,
            value: None,
            pattern: Some(pattern),
            recording_enabled: None,
            export_format: None,
        },
        Commands::Reset => Command {
            command: "reset".to_string(),
            scenario: None,
            value: None,
            pattern: None,
            recording_enabled: None,
            export_format: None,
        },
        Commands::Status => Command {
            command: "status".to_string(),
            scenario: None,
            value: None,
            pattern: None,
            recording_enabled: None,
            export_format: None,
        },
        Commands::RecordToggle { enabled } => Command {
            command: "toggle_recording".to_string(),
            scenario: None,
            value: None,
            pattern: None,
            recording_enabled: enabled,
            export_format: None,
        },
        Commands::RecordClear => Command {
            command: "clear_recording".to_string(),
            scenario: None,
            value: None,
            pattern: None,
            recording_enabled: None,
            export_format: None,
        },
        Commands::RecordDump { format } => Command {
            command: "dump_recording".to_string(),
            scenario: None,
            value: None,
            pattern: None,
            recording_enabled: None,
            export_format: Some(format),
        },
        Commands::RecordDumpCount { count } => Command {
            command: "dump_recording".to_string(),
            scenario: None,
            value: Some(count as f64),
            pattern: None,
            recording_enabled: None,
            export_format: Some("records".to_string()),
        },
        Commands::Replay => Command {
            command: "replay_recording".to_string(),
            scenario: None,
            value: None,
            pattern: None,
            recording_enabled: None,
            export_format: None,
        },
        Commands::AggregateStats { .. } => unreachable!("handled above"),
    };

    // Determine IPC backend and send command
    let ipc_backend = IpcBackend::from_env();

    let result = match ipc_backend {
        IpcBackend::Socket => send_command_socket(command),
        IpcBackend::File => send_command_file(command),
    };

    if let Err(e) = result {
        error!(backend = ?ipc_backend, error = %e, "failed to broadcast command");
        std::process::exit(1);
    }
}
