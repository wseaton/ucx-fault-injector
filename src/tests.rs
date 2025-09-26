#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use crate::ucx::*;
    use crate::strategy::FaultStrategy;
    use crate::commands::Command;
    use crate::subscriber::{handle_command, get_current_state};
    use crate::state::LOCAL_STATE;

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

        assert!(strategy.should_inject().is_some());  // X
        assert!(strategy.should_inject().is_none()); // O
        assert!(strategy.should_inject().is_some());  // X
        assert!(strategy.should_inject().is_some());  // X (wraps around)
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
        assert_eq!(crate::intercept::should_inject_fault_for_function("ucp_get_nbx"), Some(UCS_ERR_UNREACHABLE));
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
        let mut strategy = FaultStrategy::new_random_with_codes(100, vec![UCS_ERR_NO_MEMORY, UCS_ERR_BUSY]);
        for _ in 0..10 {
            if let Some(error_code) = strategy.should_inject() {
                assert!(error_code == UCS_ERR_NO_MEMORY || error_code == UCS_ERR_BUSY);
            }
        }

        // Test pattern strategy with custom error codes
        let mut strategy = FaultStrategy::new_pattern_with_codes("XOX".to_string(), vec![UCS_ERR_CANCELED, UCS_ERR_REJECTED]);
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
}