use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

// probability scaled from 0.0-100.0 to 0-10000 for 0.01% precision
const PROBABILITY_SCALE_FACTOR: u32 = 100;
const PROBABILITY_RANGE: u32 = 10000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Probability(u32); // 0-10000 for 0.01% precision

impl Probability {
    pub const ZERO: Self = Self(0);
    pub const MAX: Self = Self(PROBABILITY_RANGE);
    pub const DEFAULT: Self = Self(2500); // 25%

    pub fn from_percentage(pct: f64) -> Result<Self, &'static str> {
        if !(0.0..=100.0).contains(&pct) {
            return Err("probability must be 0.0-100.0");
        }
        Ok(Self((pct * PROBABILITY_SCALE_FACTOR as f64) as u32))
    }

    pub fn from_scaled(scaled: u32) -> Result<Self, &'static str> {
        if scaled > PROBABILITY_RANGE {
            return Err("scaled probability must be 0-10000");
        }
        Ok(Self(scaled))
    }

    pub fn to_percentage(self) -> f64 {
        self.0 as f64 / PROBABILITY_SCALE_FACTOR as f64
    }

    pub fn scaled(self) -> u32 {
        self.0
    }

    pub fn should_fire(self, random: u32) -> bool {
        random < self.0
    }
}

impl Default for Probability {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl fmt::Display for Probability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.2}%", self.to_percentage())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaultPattern(String);

impl FaultPattern {
    pub fn new(pattern: String) -> Result<Self, PatternError> {
        if pattern.is_empty() {
            return Err(PatternError::Empty);
        }
        if !pattern.chars().all(|c| c == 'X' || c == 'O') {
            return Err(PatternError::InvalidCharacter);
        }
        Ok(Self(pattern))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn into_inner(self) -> String {
        self.0
    }

    pub fn chars(&self) -> impl Iterator<Item = char> + '_ {
        self.0.chars()
    }
}

impl FromStr for FaultPattern {
    type Err = PatternError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.to_string())
    }
}

impl fmt::Display for FaultPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternError {
    Empty,
    InvalidCharacter,
}

impl fmt::Display for PatternError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "pattern cannot be empty"),
            Self::InvalidCharacter => {
                write!(f, "pattern must only contain 'X' (fault) and 'O' (pass)")
            }
        }
    }
}

impl std::error::Error for PatternError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookName {
    UcpGetNbx,
    UcpPutNbx,
    UcpEpFlushNbx,
    All,
}

impl HookName {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UcpGetNbx => "ucp_get_nbx",
            Self::UcpPutNbx => "ucp_put_nbx",
            Self::UcpEpFlushNbx => "ucp_ep_flush_nbx",
            Self::All => "all",
        }
    }

    pub fn variants() -> &'static [&'static str] {
        &["ucp_get_nbx", "ucp_put_nbx", "ucp_ep_flush_nbx", "all"]
    }
}

impl FromStr for HookName {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ucp_get_nbx" => Ok(Self::UcpGetNbx),
            "ucp_put_nbx" => Ok(Self::UcpPutNbx),
            "ucp_ep_flush_nbx" => Ok(Self::UcpEpFlushNbx),
            "all" => Ok(Self::All),
            _ => Err(format!(
                "unknown hook name: {}. valid options: {}",
                s,
                Self::variants().join(", ")
            )),
        }
    }
}

impl fmt::Display for HookName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    Pattern,
    Records,
    #[default]
    Summary,
}

impl ExportFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pattern => "pattern",
            Self::Records => "records",
            Self::Summary => "summary",
        }
    }
}

impl FromStr for ExportFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pattern" => Ok(Self::Pattern),
            "records" => Ok(Self::Records),
            "summary" => Ok(Self::Summary),
            _ => Err(format!("unknown export format: {}", s)),
        }
    }
}

impl fmt::Display for ExportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probability_from_percentage() {
        let p = Probability::from_percentage(25.0).unwrap();
        assert_eq!(p.scaled(), 2500);
        assert_eq!(p.to_percentage(), 25.0);
    }

    #[test]
    fn probability_validation() {
        assert!(Probability::from_percentage(101.0).is_err());
        assert!(Probability::from_percentage(-1.0).is_err());
        assert!(Probability::from_percentage(0.0).is_ok());
        assert!(Probability::from_percentage(100.0).is_ok());
    }

    #[test]
    fn fault_pattern_validation() {
        assert!(FaultPattern::new("XOXO".to_string()).is_ok());
        assert!(FaultPattern::new("".to_string()).is_err());
        assert!(FaultPattern::new("XYZ".to_string()).is_err());
    }

    #[test]
    fn hook_name_parsing() {
        assert_eq!(
            HookName::from_str("ucp_get_nbx").unwrap(),
            HookName::UcpGetNbx
        );
        assert_eq!(HookName::from_str("all").unwrap(), HookName::All);
        assert!(HookName::from_str("invalid").is_err());
    }
}
