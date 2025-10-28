# UCX Fault Injector

Dynamic fault injection for UCX applications via LD_PRELOAD.

## Installation

### Pre-built Binaries

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

Start your application with the injector:
```bash
LD_PRELOAD=./target/release/libucx_fault_injector.so your_app
```

Control fault injection:
```bash
./target/release/ucx-fault-client status
./target/release/ucx-fault-client toggle
./target/release/ucx-fault-client probability 2.5
./target/release/ucx-fault-client error-codes -- -3,-6,-20
./target/release/ucx-fault-client pattern XOOOOXOO
./target/release/ucx-fault-client reset
```

Recording and replay:
```bash
./target/release/ucx-fault-client record-toggle on
./target/release/ucx-fault-client record-dump pattern
./target/release/ucx-fault-client replay
```

## IPC Backends

Default is Unix domain sockets (per-process at `/tmp/ucx-fault-{pid}.sock`). For legacy file-based IPC:
```bash
UCX_FAULT_IPC_BACKEND=file LD_PRELOAD=./libucx_fault_injector.so your_app
UCX_FAULT_IPC_BACKEND=file ./ucx-fault-client status
```

## Fault Strategies

Random (probability-based):
```bash
./ucx-fault-client probability 5.0          # 5% chance per call
./ucx-fault-client error-codes -- -3,-6,-20
```

Pattern (deterministic):
```bash
./ucx-fault-client pattern XOOOOXOO         # X=fault, O=pass
./ucx-fault-client error-codes -- -3,-6
```

Default error codes: `-3` (IO_ERROR), `-6` (UNREACHABLE), `-20` (TIMED_OUT)

## UCX Error Codes

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
