# UCX Fault Injector

Dynamic fault injection for UCX applications via real-time socket API.

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
./target/release/ucx-fault-client scenario 1            # Set fault type
./target/release/ucx-fault-client reset                 # Reset defaults
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
./target/release/ucx-fault-client probability 100
```

**Result:**
```
[FAULT] INJECTED: ucp_get_nbx network/IO error (UCS_ERR_IO_ERROR = -3)
nixl._bindings.nixlBackendError: NIXL_ERR_BACKEND
```

## Fault Types

| Scenario | UCX Error | Description |
|----------|-----------|-------------|
| 0 | `UCS_ERR_IO_ERROR` | Network I/O failures |
| 1 | `UCS_ERR_UNREACHABLE` | Unreachable endpoints |
| 2 | `UCS_ERR_TIMED_OUT` | Operation timeouts |