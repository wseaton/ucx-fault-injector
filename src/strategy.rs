use crate::ucx::UcsStatus;
use std::str::FromStr;

/// granularity at which fault injection decisions are made
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultGranularity {
    /// inject faults on a per-call basis (each individual function call)
    PerCall,
    /// inject faults on a per-request basis (group calls with same arguments)
    PerRequest,
}

impl FaultGranularity {
    pub fn as_str(&self) -> &'static str {
        match self {
            FaultGranularity::PerCall => "per-call",
            FaultGranularity::PerRequest => "per-request",
        }
    }
}

impl FromStr for FaultGranularity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "per-call" | "percall" | "call" => Ok(FaultGranularity::PerCall),
            "per-request" | "perrequest" | "request" => Ok(FaultGranularity::PerRequest),
            _ => Err(format!("invalid granularity: {}", s)),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum SelectionMethod {
    Random {
        probability: u32,
    },
    Pattern {
        pattern: String,
        current_position: usize,
    },
    Replay {
        pattern: String,
        error_mapping: Vec<UcsStatus>,
        current_position: usize,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct FaultStrategy {
    pub error_codes: Vec<UcsStatus>,
    pub selection_method: SelectionMethod,
}

impl FaultStrategy {
    pub fn new_random(probability: u32) -> Self {
        Self {
            error_codes: vec![
                crate::ucx::UCS_ERR_IO_ERROR,
                crate::ucx::UCS_ERR_UNREACHABLE,
                crate::ucx::UCS_ERR_TIMED_OUT,
            ],
            selection_method: SelectionMethod::Random { probability },
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
        Self {
            error_codes: codes,
            selection_method: SelectionMethod::Random { probability },
        }
    }

    pub fn new_pattern(pattern: String) -> Self {
        Self {
            error_codes: vec![
                crate::ucx::UCS_ERR_IO_ERROR,
                crate::ucx::UCS_ERR_UNREACHABLE,
                crate::ucx::UCS_ERR_TIMED_OUT,
            ],
            selection_method: SelectionMethod::Pattern {
                pattern,
                current_position: 0,
            },
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
        Self {
            error_codes: codes,
            selection_method: SelectionMethod::Pattern {
                pattern,
                current_position: 0,
            },
        }
    }

    /// Create a replay strategy with exact error code mapping for precise replay
    pub fn new_pattern_with_mapping(pattern: String, error_code_mapping: Vec<UcsStatus>) -> Self {
        Self {
            error_codes: vec![], // Not used in replay mode
            selection_method: SelectionMethod::Replay {
                pattern,
                error_mapping: error_code_mapping,
                current_position: 0,
            },
        }
    }

    /// Create pattern from recorded calls with perfect error code preservation
    pub fn from_recorded_pattern(pattern: String, recorded_error_codes: Vec<i32>) -> Self {
        // convert i32 error codes back to UcsStatus
        let error_mapping: Vec<UcsStatus> = recorded_error_codes
            .into_iter()
            .map(|code| code as UcsStatus)
            .collect();

        if error_mapping.is_empty() {
            // fallback to regular pattern if no error codes
            Self::new_pattern(pattern)
        } else {
            Self::new_pattern_with_mapping(pattern, error_mapping)
        }
    }

    pub fn should_inject(&mut self) -> Option<UcsStatus> {
        match &mut self.selection_method {
            SelectionMethod::Random { probability } => {
                if *probability == 0 || self.error_codes.is_empty() {
                    return None;
                }

                // simple random check
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};
                use std::time::{SystemTime, UNIX_EPOCH};

                let mut hasher = DefaultHasher::new();
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
                    .hash(&mut hasher);
                let random = (hasher.finish() % 100) as u32;

                if random < *probability {
                    // randomly select an error code from the pool
                    let code_index = (hasher.finish() % self.error_codes.len() as u64) as usize;
                    Some(self.error_codes[code_index])
                } else {
                    None
                }
            }
            SelectionMethod::Pattern {
                pattern,
                current_position,
            } => {
                if pattern.is_empty() || self.error_codes.is_empty() {
                    return None;
                }

                let pattern_char = pattern
                    .chars()
                    .nth(*current_position % pattern.len())
                    .unwrap_or('O');
                *current_position += 1;

                if pattern_char == 'X' {
                    // cycle through error codes based on position
                    let code_index = (*current_position - 1) % self.error_codes.len();
                    Some(self.error_codes[code_index])
                } else {
                    None
                }
            }
            SelectionMethod::Replay {
                pattern,
                error_mapping,
                current_position,
            } => {
                if pattern.is_empty() {
                    return None;
                }

                let pattern_char = pattern
                    .chars()
                    .nth(*current_position % pattern.len())
                    .unwrap_or('O');
                *current_position += 1;

                if pattern_char == 'X' {
                    // find which 'X' this is in the pattern to map to correct error code
                    let x_count = pattern
                        .chars()
                        .take(*current_position)
                        .filter(|&c| c == 'X')
                        .count();

                    if x_count > 0 && !error_mapping.is_empty() {
                        let mapping_index = (x_count - 1) % error_mapping.len();
                        Some(error_mapping[mapping_index])
                    } else {
                        // fallback to default error if mapping is incomplete
                        Some(crate::ucx::UCS_ERR_IO_ERROR)
                    }
                } else {
                    None
                }
            }
        }
    }

    pub fn set_probability(&mut self, probability: u32) {
        if let SelectionMethod::Random {
            probability: ref mut p,
        } = &mut self.selection_method
        {
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

        // Don't update error codes for Replay mode (it uses its own error_mapping)
        if !matches!(self.selection_method, SelectionMethod::Replay { .. }) {
            self.error_codes = error_codes;
        }
    }

    pub fn set_pattern(&mut self, pattern: String) {
        match &mut self.selection_method {
            SelectionMethod::Pattern {
                pattern: ref mut p,
                current_position,
            } => {
                *p = pattern;
                *current_position = 0;
            }
            SelectionMethod::Replay {
                pattern: ref mut p,
                current_position,
                ..
            } => {
                *p = pattern;
                *current_position = 0;
            }
            _ => {
                // Convert to pattern mode
                self.selection_method = SelectionMethod::Pattern {
                    pattern,
                    current_position: 0,
                };
            }
        }
    }

    pub fn get_probability(&self) -> Option<u32> {
        match &self.selection_method {
            SelectionMethod::Random { probability } => Some(*probability),
            _ => None,
        }
    }

    pub fn get_error_codes(&self) -> &[UcsStatus] {
        match &self.selection_method {
            SelectionMethod::Replay { error_mapping, .. } => error_mapping,
            _ => &self.error_codes,
        }
    }

    pub fn get_pattern(&self) -> Option<&str> {
        match &self.selection_method {
            SelectionMethod::Random { .. } => None,
            SelectionMethod::Pattern { pattern, .. } => Some(pattern),
            SelectionMethod::Replay { pattern, .. } => Some(pattern),
        }
    }

    pub fn get_strategy_name(&self) -> &'static str {
        match &self.selection_method {
            SelectionMethod::Random { .. } => "random",
            SelectionMethod::Pattern { .. } => "pattern",
            SelectionMethod::Replay { .. } => "replay",
        }
    }
}
