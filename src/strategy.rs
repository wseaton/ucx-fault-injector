use crate::ucx::UcsStatus;

#[derive(Debug, Clone, PartialEq)]
pub enum FaultStrategy {
    Random {
        probability: u32,
        error_codes: Vec<UcsStatus>,
    },
    Pattern {
        pattern: String,
        error_codes: Vec<UcsStatus>,
        current_position: usize,
    },
}

impl FaultStrategy {
    pub fn new_random(probability: u32) -> Self {
        Self::Random {
            probability,
            error_codes: vec![
                crate::ucx::UCS_ERR_IO_ERROR,
                crate::ucx::UCS_ERR_UNREACHABLE,
                crate::ucx::UCS_ERR_TIMED_OUT,
            ],
        }
    }

    pub fn new_random_with_codes(probability: u32, error_codes: Vec<UcsStatus>) -> Self {
        let codes = if error_codes.is_empty() {
            vec![
                crate::ucx::UCS_ERR_IO_ERROR,
                crate::ucx::UCS_ERR_UNREACHABLE,
                crate::ucx::UCS_ERR_TIMED_OUT,
            ]
        } else {
            error_codes
        };
        Self::Random { probability, error_codes: codes }
    }

    pub fn new_pattern(pattern: String) -> Self {
        Self::Pattern {
            pattern,
            error_codes: vec![
                crate::ucx::UCS_ERR_IO_ERROR,
                crate::ucx::UCS_ERR_UNREACHABLE,
                crate::ucx::UCS_ERR_TIMED_OUT,
            ],
            current_position: 0,
        }
    }

    pub fn new_pattern_with_codes(pattern: String, error_codes: Vec<UcsStatus>) -> Self {
        let codes = if error_codes.is_empty() {
            vec![
                crate::ucx::UCS_ERR_IO_ERROR,
                crate::ucx::UCS_ERR_UNREACHABLE,
                crate::ucx::UCS_ERR_TIMED_OUT,
            ]
        } else {
            error_codes
        };
        Self::Pattern {
            pattern,
            error_codes: codes,
            current_position: 0,
        }
    }

    pub fn should_inject(&mut self) -> Option<UcsStatus> {
        match self {
            Self::Random { probability, error_codes } => {
                if *probability == 0 || error_codes.is_empty() {
                    return None;
                }

                // simple random check
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};
                use std::time::{SystemTime, UNIX_EPOCH};

                let mut hasher = DefaultHasher::new();
                SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos().hash(&mut hasher);
                let random = (hasher.finish() % 100) as u32;

                if random < *probability {
                    // randomly select an error code from the pool
                    let code_index = (hasher.finish() % error_codes.len() as u64) as usize;
                    Some(error_codes[code_index])
                } else {
                    None
                }
            }
            Self::Pattern { pattern, error_codes, current_position } => {
                if pattern.is_empty() || error_codes.is_empty() {
                    return None;
                }

                let pattern_char = pattern.chars().nth(*current_position % pattern.len()).unwrap_or('O');
                *current_position += 1;

                if pattern_char == 'X' {
                    // cycle through error codes based on position
                    let code_index = (*current_position - 1) % error_codes.len();
                    Some(error_codes[code_index])
                } else {
                    None
                }
            }
        }
    }

    pub fn set_probability(&mut self, probability: u32) {
        if let Self::Random { probability: ref mut p, .. } = self {
            *p = probability;
        }
    }

    pub fn set_error_codes(&mut self, codes: Vec<UcsStatus>) {
        let error_codes = if codes.is_empty() {
            vec![
                crate::ucx::UCS_ERR_IO_ERROR,
                crate::ucx::UCS_ERR_UNREACHABLE,
                crate::ucx::UCS_ERR_TIMED_OUT,
            ]
        } else {
            codes
        };

        match self {
            Self::Random { error_codes: ref mut ec, .. } => {
                *ec = error_codes;
            }
            Self::Pattern { error_codes: ref mut ec, .. } => {
                *ec = error_codes;
            }
        }
    }

    pub fn get_probability(&self) -> Option<u32> {
        match self {
            Self::Random { probability, .. } => Some(*probability),
            Self::Pattern { .. } => None,
        }
    }

    pub fn get_error_codes(&self) -> &[UcsStatus] {
        match self {
            Self::Random { error_codes, .. } => error_codes,
            Self::Pattern { error_codes, .. } => error_codes,
        }
    }

    pub fn get_pattern(&self) -> Option<&str> {
        match self {
            Self::Random { .. } => None,
            Self::Pattern { pattern, .. } => Some(pattern),
        }
    }

    pub fn get_strategy_name(&self) -> &'static str {
        match self {
            Self::Random { .. } => "random",
            Self::Pattern { .. } => "pattern",
        }
    }
}