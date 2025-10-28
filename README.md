# UCX Fault Injector

Dynamic fault injection for UCX applications via real-time file-based IPC.

## Installation

### Pre-built Binaries

Download the latest release for your platform from [GitHub Releases](https://github.com/wseaton/ucx-fault-injector/releases):

```bash
# Linux (x86_64)
curl -LO https://github.com/wseaton/ucx-fault-injector/releases/latest/download/ucx-fault-injector-linux-amd64.tar.gz
tar xzf ucx-fault-injector-linux-amd64.tar.gz
cd ucx-fault-injector-linux-amd64

# macOS (Apple Silicon)
curl -LO https://github.com/wseaton/ucx-fault-injector/releases/latest/download/ucx-fault-injector-darwin-arm64.tar.gz
tar xzf ucx-fault-injector-darwin-arm64.tar.gz
cd ucx-fault-injector-darwin-arm64

# macOS (Intel)
curl -LO https://github.com/wseaton/ucx-fault-injector/releases/latest/download/ucx-fault-injector-darwin-amd64.tar.gz
tar xzf ucx-fault-injector-darwin-amd64.tar.gz
cd ucx-fault-injector-darwin-amd64
```

Each tarball contains:
- `ucx-fault-client` - CLI tool for controlling fault injection
- `libucx_fault_injector.so` (or `.dylib` on macOS) - Shared library for LD_PRELOAD

### Building from Source

```bash
cargo build --release
```

## Usage

**Start your UCX app with fault injection:**
```bash
# If using pre-built binaries
LD_PRELOAD=./libucx_fault_injector.so your_app

# If built from source
LD_PRELOAD=./target/release/libucx_fault_injector.so your_app
```

**Control faults in real-time:**
```bash
# Fault injection commands
./ucx-fault-client status                # Check status
./ucx-fault-client toggle                # Enable/disable
./ucx-fault-client probability 0.5       # Set 0.5% fault rate (random selection)
./ucx-fault-client error-codes -- -3,-6,-20 # Set custom error codes
./ucx-fault-client pattern XOOOOXOO      # Set deterministic fault pattern
./ucx-fault-client reset                 # Reset defaults

# Recording & replay commands
./ucx-fault-client record-toggle on      # Enable call recording
./ucx-fault-client record-dump summary   # Show recording statistics
./ucx-fault-client record-dump pattern   # Export fault pattern
./ucx-fault-client replay                # Replay recorded pattern
./ucx-fault-client record-clear          # Clear recorded data
```

## Example: Testing NIXL

```bash
# Setup
uv venv nixl-test && source nixl-test/bin/activate
uv pip install nixl
curl -o nixl_example.py https://raw.githubusercontent.com/ai-dynamo/nixl/refs/tags/0.6.0/examples/python/nixl_api_example.py

# Run with fault injection
LD_PRELOAD=./libucx_fault_injector.so python nixl_example.py &

# Inject faults
./ucx-fault-client toggle
./ucx-fault-client pattern XOOOOXOO     # Fault every 1st and 6th call
./ucx-fault-client error-codes -- -3,-6    # Use IO_ERROR and UNREACHABLE
```

**Result:**
```
[FAULT] INJECTED: ucp_get_nbx network/IO error (UCS_ERR_IO_ERROR = -3)
nixl._bindings.nixlBackendError: NIXL_ERR_BACKEND
```

## Error Code System

The fault injector uses a simple error code system with two selection methods:

### Random Selection (Probability-based)
```bash
./ucx-fault-client probability 2.5       # 2.5% chance per call
./ucx-fault-client error-codes -- -3,-6,-20 # Custom error codes to select from
```
- When a fault is triggered, randomly selects from the configured error codes
- Default error codes: -3 (IO_ERROR), -6 (UNREACHABLE), -20 (TIMED_OUT)

### Pattern-based Selection (Deterministic)
```bash
./ucx-fault-client pattern XOOOOXOO      # X=fault, O=pass
./ucx-fault-client error-codes -- -3,-6     # Error codes to cycle through
```
- Pattern repeats cyclically through UCX calls
- `X` positions inject faults, `O` positions pass through normally
- Example: `XOOOOXOO` faults calls 1, 6, 9, 14, 17, 22, etc.
- Error codes are cycled through for each fault injection

## Error Code Management

### Default Error Codes
By default, the system uses these error codes:
- `UCS_ERR_IO_ERROR` (-3): Network I/O failures
- `UCS_ERR_UNREACHABLE` (-6): Unreachable endpoints
- `UCS_ERR_TIMED_OUT` (-20): Operation timeouts

### Setting Custom Error Codes

**Via CLI:**
```bash
# Set specific error codes to use for fault injection
./ucx-fault-client error-codes -- -3,-6,-20,-25

# Combined with probability (random selection)
./ucx-fault-client probability 1.5
./ucx-fault-client error-codes -- -4,-15

# Combined with pattern (deterministic cycling)
./ucx-fault-client pattern XOXO
./ucx-fault-client error-codes -- -3,-6
```

**Advanced file-based configuration:**
```bash
# Set error codes via direct file commands
echo '{"timestamp": 1640995200, "command": "set_error_codes", "pattern": "-3,-6,-20,-25"}' >> /tmp/ucx-fault-commands

# Set pattern with error codes
echo '{"timestamp": 1640995200, "command": "set_pattern", "pattern": "XOX"}' >> /tmp/ucx-fault-commands
```

**Behavior:**
- **Random selection**: Randomly selects error codes from the pool when faults are triggered
- **Pattern-based**: Cycles through error codes for each 'X' position in the pattern

## Call Recording & Replay

The fault injector now supports recording UCX calls and their fault injection decisions, enabling pattern replay and analysis.

### Recording Commands

**Enable/disable recording:**
```bash
./ucx-fault-client record-toggle         # Toggle current state
./ucx-fault-client record-toggle on      # Enable recording
./ucx-fault-client record-toggle off     # Disable recording
```

**Export recorded data:**
```bash
# High-level statistics (default)
./ucx-fault-client record-dump summary

# Fault pattern and error codes for replay
./ucx-fault-client record-dump pattern

# Detailed call records
./ucx-fault-client record-dump records

# Last N call records
./ucx-fault-client record-dump-count 50
```

**Manage recordings:**
```bash
./ucx-fault-client record-clear          # Clear buffer
./ucx-fault-client replay                # Replay pattern
```

### Export Formats

**Summary format:**
```json
{
  "recording_enabled": true,
  "total_calls": 1250,
  "fault_count": 312,
  "fault_rate": 0.2496,
  "pattern_length": 1000,
  "unique_error_codes": ["-3", "-6", "-20"]
}
```

**Pattern format:**
```json
{
  "pattern": "OOXOOOXOOOOXOO",
  "error_codes": [-3, -6, -20],
  "total_calls": 14
}
```

**Records format:**
```json
{
  "records": [
    {
      "sequence": 1,
      "timestamp_us": 1640995200000000,
      "fault_injected": false,
      "error_code": 0
    },
    {
      "sequence": 2,
      "timestamp_us": 1640995200001000,
      "fault_injected": true,
      "error_code": -3
    }
  ],
  "total_count": 2
}
```

### Workflow Examples

**Record and replay a fault pattern:**
```bash
# 1. Start recording
./ucx-fault-client record-toggle on

# 2. Run your application with some fault injection
./ucx-fault-client strategy random
./ucx-fault-client probability 5.0
# ... run your UCX application ...

# 3. Export the pattern that was generated
./ucx-fault-client record-dump pattern

# 4. Replay the exact same pattern
./ucx-fault-client replay
# ... run your UCX application again ...
```

**Analyze call patterns:**
```bash
# Get high-level statistics
./ucx-fault-client record-dump summary

# Examine recent call details
./ucx-fault-client record-dump-count 100
```

### Available UCX Error Codes
```
UCS_OK = 0                          UCS_ERR_NO_ELEM = -12
UCS_INPROGRESS = 1                  UCS_ERR_SOME_CONNECTS_FAILED = -13
UCS_ERR_NO_MESSAGE = -1             UCS_ERR_NO_DEVICE = -14
UCS_ERR_NO_RESOURCE = -2            UCS_ERR_BUSY = -15
UCS_ERR_IO_ERROR = -3               UCS_ERR_CANCELED = -16
UCS_ERR_NO_MEMORY = -4              UCS_ERR_SHMEM_SEGMENT = -17
UCS_ERR_INVALID_PARAM = -5          UCS_ERR_ALREADY_EXISTS = -18
UCS_ERR_UNREACHABLE = -6            UCS_ERR_OUT_OF_RANGE = -19
UCS_ERR_INVALID_ADDR = -7           UCS_ERR_TIMED_OUT = -20
UCS_ERR_NOT_IMPLEMENTED = -8        UCS_ERR_EXCEEDS_LIMIT = -21
UCS_ERR_MESSAGE_TRUNCATED = -9      UCS_ERR_UNSUPPORTED = -22
UCS_ERR_NO_PROGRESS = -10           UCS_ERR_REJECTED = -23
UCS_ERR_BUFFER_TOO_SMALL = -11      UCS_ERR_NOT_CONNECTED = -24
                                    UCS_ERR_CONNECTION_RESET = -25
```
