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
    /// Set fault scenario (0=network, 1=timeout, 2=memory)
    Scenario {
        /// Scenario number (0, 1, or 2)
        #[arg(value_parser = clap::value_parser!(u32).range(0..=2))]
        scenario: u32,
    },
    /// Set fault injection probability (0-100)
    Probability {
        /// Probability percentage (0-100)
        #[arg(value_parser = clap::value_parser!(u32).range(0..=100))]
        probability: u32,
    },
    /// Set fault strategy pattern
    Strategy {
        /// Pattern: 'random' for probability-based, or pattern like 'XOOOOXOO' where X=fault, O=pass
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


fn send_command_zmq(command: Command) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = zmq::Context::new();
    let publisher = ctx.socket(zmq::PUB)?;

    let broadcast_addr = "tcp://127.0.0.1:15559";
    publisher.bind(broadcast_addr)?;

    // Give ZMQ time to establish connections
    std::thread::sleep(std::time::Duration::from_millis(100));

    let command_json = serde_json::to_string(&command)?;
    publisher.send(&command_json, 0)?;

    println!("Broadcasting command: {}", command_json);
    println!("Publisher bound to: {}", broadcast_addr);

    // Give time for message to be delivered
    std::thread::sleep(std::time::Duration::from_millis(100));

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
        Commands::Scenario { scenario } => Command {
            command: "set_scenario".to_string(),
            scenario: Some(scenario),
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
        Commands::Strategy { pattern } => Command {
            command: "set_strategy".to_string(),
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

    // Send command via ZMQ broadcast
    match send_command_zmq(command) {
        Ok(()) => {
            println!("Command broadcast successfully");
        }
        Err(e) => {
            eprintln!("Error broadcasting command: {}", e);
            std::process::exit(1);
        }
    }
}