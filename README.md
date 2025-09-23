# UCX Fault Injector

Dynamic fault injection for UCX applications via real-time ZMQ broadcast API.

## Build

```bash
cargo build --release
```

## Usage

**Start your UCX app with fault injection:**
```bash
LD_PRELOAD=./target/release/libucx_fault_injector.so your_app
```

**Control faults in real-time:**
```bash
./target/release/ucx-fault-client status                # Check status
./target/release/ucx-fault-client toggle                # Enable/disable
./target/release/ucx-fault-client probability 50        # Set 50% fault rate
./target/release/ucx-fault-client strategy random       # Use probability-based faults
./target/release/ucx-fault-client strategy XOOOOXOO     # Use pattern-based faults
./target/release/ucx-fault-client reset                 # Reset defaults

# NEW: Error code pools (see Error Code Pools section)
./target/release/ucx-fault-client error-codes -3,-6,-20 # Set custom error codes
```

## Example: Testing NIXL

```bash
# Setup
uv venv nixl-test && source nixl-test/bin/activate
uv pip install nixl
curl -o nixl_example.py https://raw.githubusercontent.com/ai-dynamo/nixl/refs/tags/0.6.0/examples/python/nixl_api_example.py

# Run with fault injection
LD_PRELOAD=./target/release/libucx_fault_injector.so python nixl_example.py &

# Inject faults
./target/release/ucx-fault-client toggle
./target/release/ucx-fault-client strategy XOOOOXOO  # Fault every 1st and 6th call
```

**Result:**
```
[FAULT] INJECTED: ucp_get_nbx network/IO error (UCS_ERR_IO_ERROR = -3)
nixl._bindings.nixlBackendError: NIXL_ERR_BACKEND
```

## Fault Strategies

The fault injector supports two strategies for determining when to inject faults:

### Probability-based (Random)
```bash
./target/release/ucx-fault-client strategy random
./target/release/ucx-fault-client probability 25    # 25% chance per call
```

### Pattern-based (Deterministic)
```bash
./target/release/ucx-fault-client strategy XOOOOXOO  # X=fault, O=pass
```
- Pattern repeats cyclically through UCX calls
- `X` positions inject faults, `O` positions pass through normally
- Example: `XOOOOXOO` faults calls 1, 6, 9, 14, 17, 22, etc.

## Error Code Pools

Both strategies now support **error code pools** - arrays of UCX error codes to randomly select from or cycle through:

### Default Error Codes
By default, strategies use these error codes:
- `UCS_ERR_IO_ERROR` (-3): Network I/O failures
- `UCS_ERR_UNREACHABLE` (-6): Unreachable endpoints
- `UCS_ERR_TIMED_OUT` (-20): Operation timeouts

### Custom Error Code Pools

**ZMQ Commands:**
```json
// Random strategy with custom error codes
{"command": "set_strategy", "pattern": "random", "error_codes": [-3,-6,-20]}

// Pattern strategy with custom error codes
{"command": "set_strategy", "pattern": "XOX", "error_codes": [-4,-15]}

// Update error codes for current strategy
{"command": "set_error_codes", "error_codes": [-3,-6,-20,-25]}
```

**Behavior:**
- **Random strategy**: Randomly selects error codes from the pool when faults are injected
- **Pattern strategy**: Cycles through error codes based on pattern position (each 'X' gets the next error code)

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
