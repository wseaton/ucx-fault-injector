use std::env;
use serde::Serialize;

#[derive(Serialize)]
struct Command {
    command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    scenario: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<u32>,
}


fn print_usage() {
    println!("UCX Fault Injector Client (ZMQ Broadcast)");
    println!("Usage: ucx-fault-client <COMMAND>");
    println!();
    println!("Commands:");
    println!("  toggle                 Toggle fault injection on/off");
    println!("  scenario <0|1|2>       Set fault scenario (0=network, 1=timeout, 2=memory)");
    println!("  probability <0-100>    Set fault injection probability");
    println!("  reset                  Reset to default settings");
    println!("  status                 Show current state (broadcasts only)");
    println!();
    println!("Examples:");
    println!("  ucx-fault-client toggle");
    println!("  ucx-fault-client scenario 1");
    println!("  ucx-fault-client probability 25");
    println!("  ucx-fault-client reset");
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
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        std::process::exit(1);
    }

    let mut command_args = Vec::new();

    // Parse arguments
    for arg in &args[1..] {
        match arg.as_str() {
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            _ => {
                command_args.push(arg.clone());
            }
        }
    }

    if command_args.is_empty() {
        eprintln!("Error: No command specified");
        print_usage();
        std::process::exit(1);
    }


    // Parse command
    let command = match command_args[0].as_str() {
        "toggle" => Command {
            command: "toggle".to_string(),
            scenario: None,
            value: None,
        },
        "scenario" => {
            if command_args.len() < 2 {
                eprintln!("Error: scenario command requires a value (0, 1, or 2)");
                std::process::exit(1);
            }
            let scenario_value = command_args[1].parse().unwrap_or_else(|_| {
                eprintln!("Error: Invalid scenario value. Must be 0, 1, or 2");
                std::process::exit(1);
            });
            Command {
                command: "set_scenario".to_string(),
                scenario: Some(scenario_value),
                value: None,
            }
        },
        "probability" => {
            if command_args.len() < 2 {
                eprintln!("Error: probability command requires a value (0-100)");
                std::process::exit(1);
            }
            let prob_value = command_args[1].parse().unwrap_or_else(|_| {
                eprintln!("Error: Invalid probability value. Must be 0-100");
                std::process::exit(1);
            });
            Command {
                command: "set_probability".to_string(),
                scenario: None,
                value: Some(prob_value),
            }
        },
        "reset" => Command {
            command: "reset".to_string(),
            scenario: None,
            value: None,
        },
        "status" => Command {
            command: "status".to_string(),
            scenario: None,
            value: None,
        },
        _ => {
            eprintln!("Error: Unknown command '{}'", command_args[0]);
            print_usage();
            std::process::exit(1);
        }
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