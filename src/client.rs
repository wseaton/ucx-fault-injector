use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

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

// Response structure from server
#[derive(Deserialize, Debug)]
struct Response {
    status: String,
    message: String,
}

#[derive(Serialize)]
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
    use std::io::{BufReader, BufWriter, Write};
    use std::os::unix::net::UnixStream;

    // Discover all socket files
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

    let mut success_count = 0;
    let mut error_count = 0;

    for socket_path in sockets {
        // Extract PID from socket path
        let pid = socket_path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|s| s.strip_prefix("ucx-fault-"))
            .and_then(|s| s.strip_suffix(".sock"))
            .unwrap_or("unknown");

        // Connect to socket
        let stream = match UnixStream::connect(&socket_path) {
            Ok(s) => s,
            Err(e) => {
                warn!(pid, error = %e, "failed to connect");
                error_count += 1;
                continue;
            }
        };

        let mut writer = BufWriter::new(&stream);
        let reader = BufReader::new(&stream);

        // Send command
        if let Err(e) = serde_json::to_writer(&mut writer, &command) {
            error!(pid, error = %e, "failed to send command");
            error_count += 1;
            continue;
        }

        if let Err(e) = writer.flush() {
            error!(pid, error = %e, "failed to flush command");
            error_count += 1;
            continue;
        }

        // Read response
        let response: Response = match serde_json::from_reader(reader) {
            Ok(r) => r,
            Err(e) => {
                error!(pid, error = %e, "failed to read response");
                error_count += 1;
                continue;
            }
        };

        info!(pid, status = %response.status, message = %response.message, "command processed");
        success_count += 1;
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

fn main() {
    // initialize tracing
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .compact()
        .init();

    let cli = Cli::parse();

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
