#!/bin/bash

echo "=== UCX Fault Injection Demo ==="
echo "Starting nixl example with fault injector..."

# Start nixl example in background with UCX debug logging
source nixl-test/bin/activate
UCX_LOG_LEVEL=debug UCX_FAULT_DEBUG=1 LD_PRELOAD=./target/release/libucx_fault_injector.so python nixl_example.py &
NIXL_PID=$!

echo "nixl process started with PID: $NIXL_PID"
echo "Waiting for fault injector to initialize..."

# Wait for socket to be created (give it time to initialize)
SESSION_ID=$(ps -o sid= -p $NIXL_PID | tr -d ' ')
SOCKET_PATH="/tmp/ucx-fault-injector-session-${SESSION_ID}.sock"

echo "Expected socket path: $SOCKET_PATH"
echo "Waiting for socket to be ready..."

# Wait up to 10 seconds for socket to appear
for i in {1..10}; do
    if [ -S "$SOCKET_PATH" ]; then
        echo "Socket ready!"
        break
    fi
    echo "Waiting... ($i/10)"
    sleep 1
done

if [ ! -S "$SOCKET_PATH" ]; then
    echo "ERROR: Socket not found after 10 seconds"
    kill $NIXL_PID 2>/dev/null
    exit 1
fi

echo
echo "=== Testing Fault Injection ==="

echo "1. Checking initial status:"
./target/release/ucx-fault-client -s $SESSION_ID status

echo
echo "2. Enabling fault injection (100% probability, scenario 0 - NETWORK_ERROR):"
./target/release/ucx-fault-client -s $SESSION_ID toggle
./target/release/ucx-fault-client -s $SESSION_ID probability 100
./target/release/ucx-fault-client -s $SESSION_ID status

echo
echo "3. Observing faults for 5 seconds..."
sleep 5

echo
echo "4. Switching to scenario 1 (TIMEOUT):"
./target/release/ucx-fault-client -s $SESSION_ID scenario 1
./target/release/ucx-fault-client -s $SESSION_ID status

echo
echo "5. Observing timeout faults for 5 seconds..."
sleep 5

echo
echo "6. Switching to scenario 2 (MEMORY_ERROR):"
./target/release/ucx-fault-client -s $SESSION_ID scenario 2
./target/release/ucx-fault-client -s $SESSION_ID status

echo
echo "7. Observing memory error faults for 5 seconds..."
sleep 5

echo
echo "8. Resetting to defaults:"
./target/release/ucx-fault-client -s $SESSION_ID reset
./target/release/ucx-fault-client -s $SESSION_ID status

echo
echo "=== Demo Complete ==="
echo "Killing nixl process..."
kill $NIXL_PID 2>/dev/null
wait $NIXL_PID 2>/dev/null

echo "Demo finished!"