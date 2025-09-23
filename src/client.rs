use clap::{Parser, Subcommand};
use serde::Serialize;

#[derive(Serialize)]
struct Command {
    command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    scenario: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<u32>,
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
    /// Set fault injection probability (0-100)
    Probability {
        /// Probability percentage (0-100)
        #[arg(value_parser = clap::value_parser!(u32).range(0..=100))]
        probability: u32,
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
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};
    use nix::fcntl::{Flock, FlockArg};

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

    println!("Command written to file: {}", command_json);
    println!("Command file: {}", command_file);

    Ok(())
}

fn main() {
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
            value: Some(count),
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

    // Send command via file
    match send_command_file(command) {
        Ok(()) => {
            println!("Command broadcast successfully");
        }
        Err(e) => {
            eprintln!("Error broadcasting command: {}", e);
            std::process::exit(1);
        }
    }
}
