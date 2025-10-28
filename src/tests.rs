#[cfg(test)]
use std::sync::atomic::Ordering;

#[cfg(test)]
use crate::commands::Command;
#[cfg(test)]
use crate::state::LOCAL_STATE;
#[cfg(test)]
use crate::strategy::FaultStrategy;
#[cfg(test)]
use crate::subscriber::{get_current_state, handle_command};
#[cfg(test)]
use crate::ucx::*;

#[test]
fn test_fault_strategy_random() {
    let mut strategy = FaultStrategy::new_random(100); // 100% probability
    assert!(strategy.should_inject().is_some());

    let mut strategy = FaultStrategy::new_random(0); // 0% probability
    assert!(strategy.should_inject().is_none());
}

#[test]
fn test_fault_strategy_pattern() {
    let mut strategy = FaultStrategy::new_pattern("XOX".to_string());

    assert!(strategy.should_inject().is_some()); // X
    assert!(strategy.should_inject().is_none()); // O
    assert!(strategy.should_inject().is_some()); // X
    assert!(strategy.should_inject().is_some()); // X (wraps around)
}

#[test]
fn test_command_handling() {
    // Test toggle command
    let cmd = Command {
        command: "toggle".to_string(),
        value: None,
        pattern: None,
        error_codes: None,
        recording_enabled: None,
        export_format: None,
        hook_name: None,
    };

    let response = handle_command(cmd);
    assert_eq!(response.status, "ok");
    assert!(response.state.is_some());
}

#[test]
fn test_ucp_get_nbx_mock() {
    // Reset state first to ensure clean test
    LOCAL_STATE.enabled.store(false, Ordering::Relaxed);

    // Test fault injection logic without calling the actual intercept function
    // to avoid expensive library search during testing

    // Test with fault injection disabled
    assert!(crate::intercept::should_inject_fault().is_none());

    // Enable fault injection
    LOCAL_STATE.enabled.store(true, Ordering::Relaxed);

    // Force fault injection with 100% probability and specific error code
    {
        let mut strategy = LOCAL_STATE.strategy.lock().unwrap();
        *strategy = FaultStrategy::new_random_with_codes(100, vec![UCS_ERR_UNREACHABLE]);
    }

    // Test fault injection logic
    assert_eq!(
        crate::intercept::should_inject_fault_for_function("ucp_get_nbx"),
        Some(UCS_ERR_UNREACHABLE)
    );
}

#[test]
fn test_status_to_ptr_conversion() {
    let ptr = ucs_status_to_ptr(UCS_ERR_IO_ERROR);
    assert_eq!(ptr as isize, UCS_ERR_IO_ERROR as isize);

    let ptr = ucs_status_to_ptr(UCS_ERR_TIMED_OUT);
    assert_eq!(ptr as isize, UCS_ERR_TIMED_OUT as isize);
}

#[test]
fn test_get_current_state() {
    // Reset state first to ensure clean test
    LOCAL_STATE.enabled.store(false, Ordering::Relaxed);

    // Set a known state
    LOCAL_STATE.enabled.store(true, Ordering::Relaxed);

    {
        let mut strategy = LOCAL_STATE.strategy.lock().unwrap();
        *strategy = FaultStrategy::new_random(75);
    }

    let state = get_current_state();
    assert!(state.enabled);
    assert_eq!(state.probability, 75);
    assert_eq!(state.strategy, "random");
    assert!(!state.error_codes.is_empty());
}

#[test]
fn test_error_code_pools() {
    // Test random strategy with custom error codes
    let mut strategy =
        FaultStrategy::new_random_with_codes(100, vec![UCS_ERR_NO_MEMORY, UCS_ERR_BUSY]);
    for _ in 0..10 {
        if let Some(error_code) = strategy.should_inject() {
            assert!(error_code == UCS_ERR_NO_MEMORY || error_code == UCS_ERR_BUSY);
        }
    }

    // Test pattern strategy with custom error codes
    let mut strategy = FaultStrategy::new_pattern_with_codes(
        "XOX".to_string(),
        vec![UCS_ERR_CANCELED, UCS_ERR_REJECTED],
    );
    assert_eq!(strategy.should_inject(), Some(UCS_ERR_CANCELED)); // X (code_index = 0)
    assert_eq!(strategy.should_inject(), None); // O
    assert_eq!(strategy.should_inject(), Some(UCS_ERR_CANCELED)); // X (code_index = 0)
    assert_eq!(strategy.should_inject(), Some(UCS_ERR_REJECTED)); // X (code_index = 1)

    // Test set_error_codes
    strategy.set_error_codes(vec![UCS_ERR_TIMED_OUT]);
    assert_eq!(strategy.should_inject(), None); // O
    assert_eq!(strategy.should_inject(), Some(UCS_ERR_TIMED_OUT)); // X
}

#[test]
fn test_set_error_codes_command() {
    // Reset strategy to ensure clean test state
    {
        let mut strategy = LOCAL_STATE.strategy.lock().unwrap();
        *strategy = FaultStrategy::new_random(50); // Reset to default state
    }

    let cmd = Command {
        command: "set_error_codes".to_string(),
        value: None,
        pattern: Some("-4,-15".to_string()), // UCS_ERR_NO_MEMORY, UCS_ERR_BUSY as comma-separated string
        error_codes: None,
        recording_enabled: None,
        export_format: None,
        hook_name: None,
    };

    let response = handle_command(cmd);
    assert_eq!(response.status, "ok");
    if let Some(state) = response.state {
        assert_eq!(state.error_codes, vec![-4, -15]);
    }
}

#[test]
fn test_socket_protocol_serialization() {
    use std::io::{BufRead, BufReader, Write};

    // test command serialization with newline delimiter
    let cmd = Command {
        command: "set_probability".to_string(),
        value: Some(42.5),
        pattern: None,
        error_codes: None,
        recording_enabled: None,
        export_format: None,
        hook_name: None,
    };

    // serialize to buffer
    let mut buf = Vec::new();
    serde_json::to_writer(&mut buf, &cmd).unwrap();
    writeln!(&mut buf).unwrap();

    // deserialize from buffer
    let mut reader = BufReader::new(&buf[..]);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let deserialized: Command = serde_json::from_str(&line).unwrap();

    assert_eq!(deserialized.command, "set_probability");
    assert_eq!(deserialized.value, Some(42.5));
}

#[test]
fn test_socket_protocol_response() {
    use crate::commands::Response;
    use std::io::{BufRead, BufReader, Write};

    // create a test response
    let response = Response {
        status: "ok".to_string(),
        message: "Probability set to 50.0%".to_string(),
        state: None,
        recording_data: None,
    };

    // serialize with newline delimiter
    let mut buf = Vec::new();
    serde_json::to_writer(&mut buf, &response).unwrap();
    writeln!(&mut buf).unwrap();

    // deserialize
    let mut reader = BufReader::new(&buf[..]);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let deserialized: Response = serde_json::from_str(&line).unwrap();

    assert_eq!(deserialized.status, "ok");
    assert_eq!(deserialized.message, "Probability set to 50.0%");
}

#[test]
fn test_command_roundtrip() {
    // test probability command with float value
    let cmd = Command {
        command: "set_probability".to_string(),
        value: Some(0.5), // fractional probability
        pattern: None,
        error_codes: None,
        recording_enabled: None,
        export_format: None,
        hook_name: None,
    };

    let response = handle_command(cmd);
    assert_eq!(response.status, "ok");
    assert!(response.message.contains("0.5"));
}

#[test]
fn test_set_probability_with_float() {
    // test that float probabilities are properly converted to u32
    let cmd = Command {
        command: "set_probability".to_string(),
        value: Some(75.5),
        pattern: None,
        error_codes: None,
        recording_enabled: None,
        export_format: None,
        hook_name: None,
    };

    let response = handle_command(cmd);
    assert_eq!(response.status, "ok");

    // verify internal state was set correctly (truncated to 75)
    let state = get_current_state();
    assert_eq!(state.probability, 75);
}

#[test]
fn test_invalid_probability_range() {
    // test probability > 100
    let cmd = Command {
        command: "set_probability".to_string(),
        value: Some(150.0),
        pattern: None,
        error_codes: None,
        recording_enabled: None,
        export_format: None,
        hook_name: None,
    };

    let response = handle_command(cmd);
    assert_eq!(response.status, "error");
    assert!(response.message.contains("0.0-100.0"));

    // test negative probability
    let cmd = Command {
        command: "set_probability".to_string(),
        value: Some(-10.0),
        pattern: None,
        error_codes: None,
        recording_enabled: None,
        export_format: None,
        hook_name: None,
    };

    let response = handle_command(cmd);
    assert_eq!(response.status, "error");
}
