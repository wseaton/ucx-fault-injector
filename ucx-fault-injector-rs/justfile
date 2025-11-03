# UCX Fault Injector Justfile

# Default target
default: build

# Build the fault injector library
build:
    LD_LIBRARY_PATH=$HOME/ucx/lib:${LD_LIBRARY_PATH:-} cargo build --release

# Build debug version
build-debug:
    LD_LIBRARY_PATH=$HOME/ucx/lib:${LD_LIBRARY_PATH:-} cargo build

# Clean build artifacts
clean:
    cargo clean

# Check for UCX installation
check-ucx:
    @echo "Checking for UCX installation..."
    @if [ -d "$HOME/ucx" ]; then \
        echo "UCX found at: $HOME/ucx"; \
        echo "UCX headers: $HOME/ucx/include"; \
        echo "UCX libraries: $HOME/ucx/lib"; \
        ls -la $HOME/ucx/lib/libucp* || echo "Warning: UCX libraries not found"; \
    else \
        echo "UCX not found at $HOME/ucx"; \
        exit 1; \
    fi

# Build with explicit UCX linking
build-with-ucx: check-ucx
    LD_LIBRARY_PATH=$HOME/ucx/lib:${LD_LIBRARY_PATH:-} cargo build --release

# Install the library to system location
install: build
    sudo cp target/release/libucx_fault_injector.so /usr/local/lib/
    sudo ldconfig

# Test the fault injector with a simple program
test-inject:
    #!/usr/bin/env bash
    if [ ! -f target/release/libucx_fault_injector.so ]; then
        echo "Library not found. Run 'just build' first."
        exit 1
    fi
    echo "Testing fault injection library..."
    echo "Library built at: target/release/libucx_fault_injector.so"
    echo "Use with: LD_PRELOAD=./target/release/libucx_fault_injector.so your_ucx_program"

# Format code
fmt:
    cargo fmt

# Run clippy lints
lint:
    cargo clippy -- -D warnings

# Check everything
check: fmt lint build

# Bump version (patch, minor, or major) and create release
bump level="patch":
    #!/usr/bin/env bash
    set -e

    # check if cargo-edit is installed
    if ! command -v cargo-set-version &> /dev/null; then
        echo "❌ cargo-edit not installed. Installing..."
        cargo install cargo-edit
    fi

    # get current version
    OLD_VERSION=$(grep -m1 'version = ' Cargo.toml | cut -d'"' -f2)
    echo "Current version: ${OLD_VERSION}"

    # bump version based on level
    cargo set-version --bump {{level}}

    # get new version
    NEW_VERSION=$(grep -m1 'version = ' Cargo.toml | cut -d'"' -f2)
    TAG="v${NEW_VERSION}"

    echo "Bumped version: ${OLD_VERSION} → ${NEW_VERSION}"

    # commit changes
    git add Cargo.toml Cargo.lock
    git commit -m "bump version to ${NEW_VERSION}"

    # create and push tag
    git tag -a "${TAG}" -m "Release ${TAG}"

    echo "✅ Version bumped to ${NEW_VERSION}"
    echo "✅ Changes committed and tagged as ${TAG}"
    echo ""
    echo "Push with: git push && git push origin ${TAG}"

# Show help for signal-based fault control
help-signals:
    @echo "UCX Fault Injector Signal Controls:"
    @echo "  kill -USR1 <pid>  - Toggle fault injection on/off"
    @echo "  kill -USR2 <pid>  - Cycle through fault scenarios"
    @echo "  kill -RTMIN+1 <pid> - Increase fault probability by 10%"
    @echo "  kill -RTMIN+2 <pid> - Reset to default settings"
    @echo ""
    @echo "Fault Scenarios:"
    @echo "  0: NETWORK_ERROR - Returns UCS_ERR_IO_ERROR"
    @echo "  1: TIMEOUT       - Adds 5 second delay"
    @echo "  2: MEMORY_ERROR  - Returns UCS_ERR_CANCELED"

# Create a test C program to verify the fault injector works
create-test-program:
    #!/usr/bin/env bash
    cat > test_program.c << 'EOF'
    #include <stdio.h>
    #include <stdint.h>
    #include <dlfcn.h>
    #include <unistd.h>

    // Mock UCX types for testing
    typedef int ucs_status_t;
    typedef void* ucp_worker_h;
    typedef void* ucp_ep_h;
    typedef void* ucp_ep_params_t;
    typedef void* ucp_rkey_h;

    int main() {
        printf("Testing UCX Fault Injector\n");
        printf("PID: %d\n", getpid());

        // These will be intercepted by our fault injector
        extern ucs_status_t ucp_ep_create(ucp_worker_h, const ucp_ep_params_t*, ucp_ep_h*);
        extern ucs_status_t ucp_put(ucp_ep_h, const void*, size_t, uint64_t, ucp_rkey_h);
        extern ucs_status_t ucp_get(ucp_ep_h, void*, size_t, uint64_t, ucp_rkey_h);

        printf("Testing ucp_ep_create...\n");
        ucp_ep_h ep;
        ucs_status_t status = ucp_ep_create(NULL, NULL, &ep);
        printf("ucp_ep_create returned: %d\n", status);

        printf("Testing ucp_put...\n");
        char buffer[100] = "test data";
        status = ucp_put(ep, buffer, sizeof(buffer), 0, NULL);
        printf("ucp_put returned: %d\n", status);

        printf("Testing ucp_get...\n");
        status = ucp_get(ep, buffer, sizeof(buffer), 0, NULL);
        printf("ucp_get returned: %d\n", status);

        printf("Send signals to control fault injection:\n");
        printf("  kill -USR1 %d  # toggle faults\n", getpid());
        printf("  kill -USR2 %d  # cycle scenarios\n", getpid());

        sleep(10);  // Give time to send signals
        return 0;
    }
    EOF
    LD_LIBRARY_PATH=$HOME/ucx/lib gcc -o test_program test_program.c -ldl -L$HOME/ucx/lib -lucp
    echo "Test program created: ./test_program"
    echo "Run with: LD_PRELOAD=./target/release/libucx_fault_injector.so ./test_program"

# Run the test program with fault injection
test-run: build create-test-program
    LD_LIBRARY_PATH=$HOME/ucx/lib LD_PRELOAD=./target/release/libucx_fault_injector.so ./test_program

# Test with UCX's own perftest tool (loopback test)
test-ucx-perftest: build
    #!/usr/bin/env bash
    echo "Testing fault injector with UCX perftest (loopback test)..."
    echo "Starting UCX perftest with fault injection enabled..."
    echo "PID will be shown - use signals to control faults"
    echo ""
    echo "Signal commands (run in another terminal):"
    echo "  kill -USR1 \$PID    # toggle fault injection"
    echo "  kill -USR2 \$PID    # cycle fault scenarios"
    echo "  kill -RTMIN+1 \$PID # increase probability"
    echo "  kill -RTMIN+2 \$PID # reset settings"
    echo ""
    LD_LIBRARY_PATH=$HOME/ucx/lib LD_PRELOAD=./target/release/libucx_fault_injector.so $HOME/ucx/bin/ucx_perftest -t put_lat -n 100 -s 1024 127.0.0.1

# Test with UCX info tool
test-ucx-info: build
    LD_LIBRARY_PATH=$HOME/ucx/lib LD_PRELOAD=./target/release/libucx_fault_injector.so $HOME/ucx/bin/ucx_info -d

# Automated fault injection demo with server-client perftest
test-automated: build
    #!/usr/bin/env bash
    echo "=== Automated UCX Fault Injection Demo ==="
    echo ""

    # Start server in background
    echo "Starting UCX perftest server..."
    LD_LIBRARY_PATH=$HOME/ucx/lib LD_PRELOAD=./target/release/libucx_fault_injector.so \
        $HOME/ucx/bin/ucx_perftest -t put_lat -n 1000 -s 1024 &
    SERVER_PID=$!
    echo "Server PID: $SERVER_PID"
    sleep 2

    # Start client and capture its PID
    echo "Starting UCX perftest client with fault injection..."
    LD_LIBRARY_PATH=$HOME/ucx/lib LD_PRELOAD=./target/release/libucx_fault_injector.so \
        $HOME/ucx/bin/ucx_perftest -t put_lat -n 1000 -s 1024 127.0.0.1 &
    CLIENT_PID=$!
    echo "Client PID: $CLIENT_PID"

    # Let it run normally for a bit
    echo ""
    echo "Running normally for 3 seconds..."
    sleep 3

    # Enable fault injection
    echo "Enabling fault injection..."
    kill -USR1 $CLIENT_PID
    sleep 2

    # Cycle through fault scenarios
    echo "Cycling to timeout scenario..."
    kill -USR2 $CLIENT_PID
    sleep 3

    echo "Cycling to memory error scenario..."
    kill -USR2 $CLIENT_PID
    sleep 2

    # Increase probability
    echo "Increasing fault probability..."
    kill -RTMIN+1 $CLIENT_PID 2>/dev/null || kill -TERM $CLIENT_PID
    sleep 2

    # Reset and disable
    echo "Resetting fault injection..."
    kill -RTMIN+2 $CLIENT_PID 2>/dev/null || kill -QUIT $CLIENT_PID
    sleep 1

    echo "Disabling fault injection..."
    kill -USR1 $CLIENT_PID
    sleep 2

    # Cleanup
    echo ""
    echo "Cleaning up processes..."
    kill $CLIENT_PID $SERVER_PID 2>/dev/null
    wait 2>/dev/null
    echo "Demo complete!"

# Quick automated test with a simple workload
test-quick-demo: build
    #!/usr/bin/env bash
    echo "=== Quick UCX Fault Injection Demo ==="
    echo ""

    # Use a very short latency test with random port to avoid conflicts
    echo "Running short UCX latency test with fault injection..."
    RANDOM_PORT=$((20000 + RANDOM % 10000))
    echo "Using port $RANDOM_PORT to avoid conflicts"
    echo ""
    echo "Watch for 'FAULT INJECTED:' messages showing our interceptor working!"
    echo ""
    UCX_LOG_LEVEL=debug UCX_LOG_FILE=ucx_debug.log LD_LIBRARY_PATH=$HOME/ucx/lib LD_PRELOAD=./target/release/libucx_fault_injector.so \
        timeout 5s $HOME/ucx/bin/ucx_perftest -t put_lat -d memory -n 10 -s 64 -p $RANDOM_PORT &
    TEST_PID=$!
    echo "Test PID: $TEST_PID"

    sleep 0.5
    echo "Enabling fault injection..."
    kill -USR1 $TEST_PID 2>/dev/null

    sleep 1
    echo "Switching to timeout scenario (5s delays)..."
    kill -USR2 $TEST_PID 2>/dev/null

    sleep 3
    echo "Switching to memory error scenario..."
    kill -USR2 $TEST_PID 2>/dev/null

    sleep 1
    echo "Increasing fault probability to 50%..."
    kill -RTMIN+1 $TEST_PID 2>/dev/null || echo "Using fallback signal"
    kill -RTMIN+1 $TEST_PID 2>/dev/null || echo "Using fallback signal"
    kill -RTMIN+1 $TEST_PID 2>/dev/null || echo "Using fallback signal"
    kill -RTMIN+1 $TEST_PID 2>/dev/null || echo "Using fallback signal"

    sleep 3
    echo "Disabling fault injection..."
    kill -USR1 $TEST_PID 2>/dev/null

    # Let it finish or timeout
    wait $TEST_PID 2>/dev/null
    echo "Demo complete!"
    echo ""
    echo "=== UCX Debug Log (first 50 lines) ==="
    head -50 ucx_debug.log 2>/dev/null || echo "No debug log found"
