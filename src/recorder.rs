use std::sync::atomic::{AtomicU64, AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use std::cell::UnsafeCell;
use serde::{Serialize, Deserialize};
use crate::ucx::UcsStatus;

/// Maximum number of call records in the ring buffer
pub const MAX_CALL_RECORDS: usize = 8192;

/// A single recorded call with its fault injection decision
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
}

impl CallRecord {
    pub fn new(sequence: u64, fault_injected: bool, error_code: UcsStatus) -> Self {
        let timestamp_us = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        Self {
            sequence,
            timestamp_us,
            fault_injected,
            error_code: if fault_injected { error_code } else { 0 },
            function_hash: Self::hash_function_name("ucp_get_nbx"),
        }
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
        if self.fault_injected { 'X' } else { 'O' }
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
        };

        Self {
            write_index: AtomicU64::new(0),
            total_records: AtomicU64::new(0),
            recording_enabled: AtomicU32::new(1), // enabled by default
            generation: AtomicU64::new(1),
            _reserved: [0; 4],
            records: UnsafeCell::new([EMPTY_RECORD; MAX_CALL_RECORDS]),
        }
    }

    /// Record a new call (thread-safe, lock-free)
    pub fn record_call(&self, fault_injected: bool, error_code: UcsStatus) {
        if self.recording_enabled.load(Ordering::Relaxed) == 0 {
            return;
        }

        let sequence = self.total_records.fetch_add(1, Ordering::Relaxed);
        let record = CallRecord::new(sequence, fault_injected, error_code);

        // get write position and advance atomically
        let write_pos = self.write_index.fetch_add(1, Ordering::Relaxed) % MAX_CALL_RECORDS as u64;

        // write the record (safe due to fixed array size and exclusive write access to this index)
        unsafe {
            let records_array = &mut *self.records.get();
            records_array[write_pos as usize] = record;
        }
    }

    /// Enable or disable recording
    pub fn set_recording_enabled(&self, enabled: bool) {
        self.recording_enabled.store(if enabled { 1 } else { 0 }, Ordering::Relaxed);
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
        let total_records = self.total_records.load(Ordering::Relaxed);
        if total_records == 0 {
            return String::new();
        }

        let record_count = std::cmp::min(total_records as usize, MAX_CALL_RECORDS);
        let mut pattern = String::with_capacity(record_count);

        // determine starting position based on whether we've wrapped around
        let start_index = if total_records as usize <= MAX_CALL_RECORDS {
            0
        } else {
            (self.write_index.load(Ordering::Relaxed) % MAX_CALL_RECORDS as u64) as usize
        };

        // read records in chronological order
        for i in 0..record_count {
            let record_index = (start_index + i) % MAX_CALL_RECORDS;
            let record = unsafe { (*self.records.get())[record_index] };

            // only include records that have been written (sequence > 0)
            if record.sequence > 0 {
                pattern.push(record.to_pattern_char());
            }
        }

        pattern
    }

    /// Extract error codes used in recorded faults
    pub fn extract_error_codes(&self) -> Vec<i32> {
        let total_records = self.total_records.load(Ordering::Relaxed);
        if total_records == 0 {
            return Vec::new();
        }

        let record_count = std::cmp::min(total_records as usize, MAX_CALL_RECORDS);
        let mut error_codes = Vec::new();

        let start_index = if total_records as usize <= MAX_CALL_RECORDS {
            0
        } else {
            (self.write_index.load(Ordering::Relaxed) % MAX_CALL_RECORDS as u64) as usize
        };

        for i in 0..record_count {
            let record_index = (start_index + i) % MAX_CALL_RECORDS;
            let record = unsafe { (*self.records.get())[record_index] };

            if record.sequence > 0 && record.fault_injected && record.error_code != 0
                && !error_codes.contains(&record.error_code) {
                    error_codes.push(record.error_code);
                }
        }

        error_codes
    }

    /// Get a snapshot of recent records for inspection
    pub fn get_recent_records(&self, count: usize) -> Vec<CallRecord> {
        let total_records = self.total_records.load(Ordering::Relaxed);
        if total_records == 0 {
            return Vec::new();
        }

        let available_records = std::cmp::min(total_records as usize, MAX_CALL_RECORDS);
        let requested_count = std::cmp::min(count, available_records);
        let mut records = Vec::with_capacity(requested_count);

        // get the most recent records
        let current_write_pos = self.write_index.load(Ordering::Relaxed) as usize;

        for i in 0..requested_count {
            let record_index = if current_write_pos > i {
                (current_write_pos - i - 1) % MAX_CALL_RECORDS
            } else {
                (MAX_CALL_RECORDS + current_write_pos - i - 1) % MAX_CALL_RECORDS
            };

            let record = unsafe { (*self.records.get())[record_index] };
            if record.sequence > 0 {
                records.push(record);
            }
        }

        // reverse to get chronological order (oldest first)
        records.reverse();
        records
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
}

impl From<CallRecord> for SerializableCallRecord {
    fn from(record: CallRecord) -> Self {
        Self {
            sequence: record.sequence,
            timestamp_us: record.timestamp_us,
            fault_injected: record.fault_injected,
            error_code: record.error_code,
            function_name: "ucp_get_nbx".to_string(), // for now, only this function
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

        let record_count = std::cmp::min(total_records as usize, MAX_CALL_RECORDS);
        let mut backed_up_records = Vec::with_capacity(record_count);

        // determine starting position for chronological order
        let start_index = if total_records as usize <= MAX_CALL_RECORDS {
            0
        } else {
            (self.write_index.load(Ordering::Relaxed) % MAX_CALL_RECORDS as u64) as usize
        };

        // copy records in chronological order
        for i in 0..record_count {
            let record_index = (start_index + i) % MAX_CALL_RECORDS;
            let record = unsafe { (*self.records.get())[record_index] };

            if record.sequence > 0 {
                backed_up_records.push(record);
            }
        }

        CallRecordBackup {
            records: backed_up_records,
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
        self.total_records.store(backup.total_records, Ordering::Relaxed);
        self.write_index.store(backup.write_index, Ordering::Relaxed);
        self.recording_enabled.store(backup.recording_enabled, Ordering::Relaxed);
        self.generation.store(backup.generation + 1, Ordering::Relaxed); // increment generation

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