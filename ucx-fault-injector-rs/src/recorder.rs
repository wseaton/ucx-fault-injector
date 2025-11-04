use crate::ucx::UcsStatus;
use serde::{Deserialize, Serialize};
use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum number of call records in the ring buffer
pub const MAX_CALL_RECORDS: usize = 8192;

/// Function type enumeration
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FunctionType {
    UcpGetNbx = 0,
    UcpPutNbx = 1,
    UcpEpFlushNbx = 2,
    UcpRequestCheckStatus = 3,
}

impl FunctionType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::UcpGetNbx),
            1 => Some(Self::UcpPutNbx),
            2 => Some(Self::UcpEpFlushNbx),
            3 => Some(Self::UcpRequestCheckStatus),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UcpGetNbx => "ucp_get_nbx",
            Self::UcpPutNbx => "ucp_put_nbx",
            Self::UcpEpFlushNbx => "ucp_ep_flush_nbx",
            Self::UcpRequestCheckStatus => "ucp_request_check_status",
        }
    }
}

/// parameters for a UCX function call
#[derive(Debug, Clone, Copy)]
pub struct CallParams {
    pub function_type: FunctionType,
    pub transfer_size: u64,
    pub remote_addr: u64,
    pub endpoint: u64,
    pub rkey: u64,
}

/// A single recorded call with its fault injection decision and parameters
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CallRecord {
    /// Sequence number of the call
    pub sequence: u64,
    /// Timestamp when the call was made (microseconds since epoch)
    pub timestamp_us: u64,
    /// Whether a fault was injected (true = X, false = O)
    pub fault_injected: bool,
    /// Error code that was injected (0 if no fault)
    pub error_code: i32,
    /// Function name hash (for future extensibility)
    pub function_hash: u32,

    // function parameters for detailed analysis
    /// Function type (0=get, 1=put, 2=flush)
    pub function_type: u8,
    /// Transfer size in bytes (0 for flush operations)
    pub transfer_size: u64,
    /// Remote memory address (0 for flush operations)
    pub remote_addr: u64,
    /// Endpoint handle (cast to u64)
    pub endpoint: u64,
    /// Remote key handle (cast to u64, 0 for flush operations)
    pub rkey: u64,
}

impl CallRecord {
    /// Create a new call record with function parameters
    pub fn new_with_params(
        sequence: u64,
        fault_injected: bool,
        error_code: UcsStatus,
        params: &CallParams,
    ) -> Self {
        let timestamp_us = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        Self {
            sequence,
            timestamp_us,
            fault_injected,
            error_code: if fault_injected { error_code } else { 0 },
            function_hash: Self::hash_function_name(params.function_type.as_str()),
            function_type: params.function_type as u8,
            transfer_size: params.transfer_size,
            remote_addr: params.remote_addr,
            endpoint: params.endpoint,
            rkey: params.rkey,
        }
    }

    /// Create a new call record (legacy, for backwards compatibility)
    pub fn new(sequence: u64, fault_injected: bool, error_code: UcsStatus) -> Self {
        let params = CallParams {
            function_type: FunctionType::UcpGetNbx,
            transfer_size: 0,
            remote_addr: 0,
            endpoint: 0,
            rkey: 0,
        };
        Self::new_with_params(sequence, fault_injected, error_code, &params)
    }

    /// Generate a hash for function names for future extensibility
    fn hash_function_name(name: &str) -> u32 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        name.hash(&mut hasher);
        hasher.finish() as u32
    }

    /// Get the pattern character for this record
    pub fn to_pattern_char(&self) -> char {
        if self.fault_injected {
            'X'
        } else {
            'O'
        }
    }
}

/// Ring buffer for storing call records in shared memory
#[repr(C)]
pub struct CallRecordBuffer {
    /// Current write position in the ring buffer
    pub write_index: AtomicU64,
    /// Total number of records written (can exceed buffer size)
    pub total_records: AtomicU64,
    /// Whether recording is enabled
    pub recording_enabled: AtomicU32,
    /// Generation counter for detecting buffer resets
    pub generation: AtomicU64,
    /// Reserved for future use
    _reserved: [u64; 4],
    /// The actual ring buffer of call records (using UnsafeCell for interior mutability)
    records: UnsafeCell<[CallRecord; MAX_CALL_RECORDS]>,
}

// Safety: CallRecordBuffer is safe to share between threads because:
// 1. All atomic operations are thread-safe
// 2. The UnsafeCell is only accessed in a controlled manner with proper synchronization
// 3. Writers use atomic fetch_add to get exclusive index access
// 4. Readers access stable data (records only written once at each index)
unsafe impl Send for CallRecordBuffer {}
unsafe impl Sync for CallRecordBuffer {}

impl Default for CallRecordBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl CallRecordBuffer {
    pub const fn new() -> Self {
        // can't use CallRecord::default() in const context, so initialize manually
        const EMPTY_RECORD: CallRecord = CallRecord {
            sequence: 0,
            timestamp_us: 0,
            fault_injected: false,
            error_code: 0,
            function_hash: 0,
            function_type: 0,
            transfer_size: 0,
            remote_addr: 0,
            endpoint: 0,
            rkey: 0,
        };

        Self {
            write_index: AtomicU64::new(0),
            total_records: AtomicU64::new(0),
            recording_enabled: AtomicU32::new(0), // disabled by default for minimal overhead
            generation: AtomicU64::new(1),
            _reserved: [0; 4],
            records: UnsafeCell::new([EMPTY_RECORD; MAX_CALL_RECORDS]),
        }
    }

    /// Record a new call with full parameters (thread-safe, lock-free)
    pub fn record_call_with_params(
        &self,
        fault_injected: bool,
        error_code: UcsStatus,
        params: &CallParams,
    ) {
        if self.recording_enabled.load(Ordering::Relaxed) == 0 {
            return;
        }

        let sequence = self.total_records.fetch_add(1, Ordering::Relaxed);
        let record = CallRecord::new_with_params(sequence, fault_injected, error_code, params);

        // get write position and advance atomically
        let write_pos = self.write_index.fetch_add(1, Ordering::Relaxed) % MAX_CALL_RECORDS as u64;

        // write the record (safe due to fixed array size and exclusive write access to this index)
        unsafe {
            let records_array = &mut *self.records.get();
            records_array[write_pos as usize] = record;
        }
    }

    /// Record a new call (legacy, for backwards compatibility)
    pub fn record_call(&self, fault_injected: bool, error_code: UcsStatus) {
        let params = CallParams {
            function_type: FunctionType::UcpGetNbx,
            transfer_size: 0,
            remote_addr: 0,
            endpoint: 0,
            rkey: 0,
        };
        self.record_call_with_params(fault_injected, error_code, &params);
    }

    /// Enable or disable recording
    pub fn set_recording_enabled(&self, enabled: bool) {
        self.recording_enabled
            .store(if enabled { 1 } else { 0 }, Ordering::Relaxed);
    }

    /// Check if recording is enabled
    pub fn is_recording_enabled(&self) -> bool {
        self.recording_enabled.load(Ordering::Relaxed) != 0
    }

    /// Clear all records and reset the buffer
    pub fn clear(&self) {
        const EMPTY_RECORD: CallRecord = CallRecord {
            sequence: 0,
            timestamp_us: 0,
            fault_injected: false,
            error_code: 0,
            function_hash: 0,
            function_type: 0,
            transfer_size: 0,
            remote_addr: 0,
            endpoint: 0,
            rkey: 0,
        };

        self.write_index.store(0, Ordering::Relaxed);
        self.total_records.store(0, Ordering::Relaxed);
        self.generation.fetch_add(1, Ordering::Relaxed);

        // zero out the records array
        unsafe {
            let records_array = &mut *self.records.get();
            *records_array = [EMPTY_RECORD; MAX_CALL_RECORDS];
        }
    }

    /// Get the current generation counter
    pub fn get_generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }

    /// Get total number of records ever written
    pub fn get_total_records(&self) -> u64 {
        self.total_records.load(Ordering::Relaxed)
    }

    /// Get current number of valid records in buffer
    pub fn get_record_count(&self) -> usize {
        let total = self.total_records.load(Ordering::Relaxed);
        std::cmp::min(total as usize, MAX_CALL_RECORDS)
    }

    /// Generate a pattern string from recorded calls
    pub fn generate_pattern(&self) -> String {
        self.iter_records().map(|r| r.to_pattern_char()).collect()
    }

    /// Extract error codes used in recorded faults
    pub fn extract_error_codes(&self) -> Vec<i32> {
        let mut error_codes = Vec::new();
        for record in self.iter_records() {
            if record.fault_injected
                && record.error_code != 0
                && !error_codes.contains(&record.error_code)
            {
                error_codes.push(record.error_code);
            }
        }
        error_codes
    }

    /// Get a snapshot of recent records for inspection
    pub fn get_recent_records(&self, count: usize) -> Vec<CallRecord> {
        self.iter_records()
            .rev()
            .take(count)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect()
    }

    pub fn iter_records(&self) -> RecordIterator<'_> {
        RecordIterator::new(self)
    }
}

pub struct RecordIterator<'a> {
    buffer: &'a CallRecordBuffer,
    current: usize,
    remaining: usize,
    start_index: usize,
}

impl<'a> RecordIterator<'a> {
    fn new(buffer: &'a CallRecordBuffer) -> Self {
        let total_records = buffer.total_records.load(Ordering::Relaxed);
        let record_count = std::cmp::min(total_records as usize, MAX_CALL_RECORDS);

        let start_index = if total_records as usize <= MAX_CALL_RECORDS {
            0
        } else {
            (buffer.write_index.load(Ordering::Relaxed) % MAX_CALL_RECORDS as u64) as usize
        };

        Self {
            buffer,
            current: 0,
            remaining: record_count,
            start_index,
        }
    }
}

impl<'a> Iterator for RecordIterator<'a> {
    type Item = CallRecord;

    fn next(&mut self) -> Option<Self::Item> {
        while self.remaining > 0 {
            let record_index = (self.start_index + self.current) % MAX_CALL_RECORDS;
            self.current += 1;
            self.remaining -= 1;

            let record = unsafe { (*self.buffer.records.get())[record_index] };
            if record.sequence > 0 {
                return Some(record);
            }
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.remaining))
    }
}

impl<'a> DoubleEndedIterator for RecordIterator<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        while self.remaining > 0 {
            self.remaining -= 1;
            let record_index = (self.start_index + self.remaining) % MAX_CALL_RECORDS;

            let record = unsafe { (*self.buffer.records.get())[record_index] };
            if record.sequence > 0 {
                return Some(record);
            }
        }
        None
    }
}

/// Serializable version of call records for export
#[derive(Serialize, Deserialize, Debug)]
pub struct SerializableCallRecord {
    pub sequence: u64,
    pub timestamp_us: u64,
    pub fault_injected: bool,
    pub error_code: i32,
    pub function_name: String,
    pub transfer_size: u64,
    pub remote_addr: String,
    pub endpoint: String,
    pub rkey: String,
}

impl From<CallRecord> for SerializableCallRecord {
    fn from(record: CallRecord) -> Self {
        let function_name = FunctionType::from_u8(record.function_type)
            .map(|ft| ft.as_str().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        Self {
            sequence: record.sequence,
            timestamp_us: record.timestamp_us,
            fault_injected: record.fault_injected,
            error_code: record.error_code,
            function_name,
            transfer_size: record.transfer_size,
            remote_addr: format!("0x{:x}", record.remote_addr),
            endpoint: format!("0x{:x}", record.endpoint),
            rkey: format!("0x{:x}", record.rkey),
        }
    }
}

/// Backup structure for preserving recording data during shared memory reinitialization
#[derive(Debug, Clone)]
pub struct CallRecordBackup {
    pub records: Vec<CallRecord>,
    pub total_records: u64,
    pub write_index: u64,
    pub recording_enabled: u32,
    pub generation: u64,
}

impl CallRecordBackup {
    pub fn empty() -> Self {
        Self {
            records: Vec::new(),
            total_records: 0,
            write_index: 0,
            recording_enabled: 1, // keep recording enabled by default
            generation: 1,
        }
    }
}

/// Recording statistics and summary
#[derive(Serialize, Deserialize, Debug)]
pub struct RecordingSummary {
    pub total_calls: u64,
    pub faults_injected: u64,
    pub fault_rate: f64,
    pub pattern_length: usize,
    pub pattern: String,
    pub error_codes_used: Vec<i32>,
    pub recording_enabled: bool,
    pub buffer_wrapped: bool,
}

impl CallRecordBuffer {
    /// Create a backup of the current recording state
    pub fn backup_state(&self) -> CallRecordBackup {
        let total_records = self.total_records.load(Ordering::Relaxed);
        if total_records == 0 {
            return CallRecordBackup::empty();
        }

        CallRecordBackup {
            records: self.iter_records().collect(),
            total_records,
            write_index: self.write_index.load(Ordering::Relaxed),
            recording_enabled: self.recording_enabled.load(Ordering::Relaxed),
            generation: self.generation.load(Ordering::Relaxed),
        }
    }

    /// Restore from a backup (preserving existing data if backup is valid)
    pub fn restore_from_backup(&self, backup: CallRecordBackup) {
        if backup.records.is_empty() {
            return; // nothing to restore
        }

        // restore metadata
        self.total_records
            .store(backup.total_records, Ordering::Relaxed);
        self.write_index
            .store(backup.write_index, Ordering::Relaxed);
        self.recording_enabled
            .store(backup.recording_enabled, Ordering::Relaxed);
        self.generation
            .store(backup.generation + 1, Ordering::Relaxed); // increment generation

        // restore records to buffer
        unsafe {
            let records_array = &mut *self.records.get();

            // clear existing records first
            const EMPTY_RECORD: CallRecord = CallRecord {
                sequence: 0,
                timestamp_us: 0,
                fault_injected: false,
                error_code: 0,
                function_hash: 0,
                function_type: 0,
                transfer_size: 0,
                remote_addr: 0,
                endpoint: 0,
                rkey: 0,
            };
            *records_array = [EMPTY_RECORD; MAX_CALL_RECORDS];

            // restore backed up records
            for (i, &record) in backup.records.iter().enumerate() {
                if i < MAX_CALL_RECORDS {
                    records_array[i] = record;
                }
            }
        }
    }

    /// Generate a comprehensive summary of the recording
    pub fn generate_summary(&self) -> RecordingSummary {
        let total_calls = self.total_records.load(Ordering::Relaxed);
        let pattern = self.generate_pattern();
        let faults_injected = pattern.chars().filter(|&c| c == 'X').count() as u64;
        let fault_rate = if total_calls > 0 {
            faults_injected as f64 / total_calls as f64
        } else {
            0.0
        };

        RecordingSummary {
            total_calls,
            faults_injected,
            fault_rate,
            pattern_length: pattern.len(),
            pattern,
            error_codes_used: self.extract_error_codes(),
            recording_enabled: self.is_recording_enabled(),
            buffer_wrapped: total_calls as usize > MAX_CALL_RECORDS,
        }
    }
}
