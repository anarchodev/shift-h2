#!/usr/bin/env bash
#
# Load test for h2c_echo using h2load (nghttp2)
#
# Usage:
#   ./scripts/load_test.sh [profile]
#
# Profiles:
#   quick       -  1k requests, 10 clients, 10 streams (sanity check)
#   moderate    - 100k requests, 100 clients, 100 streams (default)
#   heavy       -   1M requests, 500 clients, 256 streams
#   sustained   - 10M requests, 1000 clients, 256 streams, 60s warmup
#
# Environment overrides:
#   HOST        - target host (default: 127.0.0.1)
#   PORT        - target port (default: 9000)
#   THREADS     - h2load threads (default: auto based on profile)
#   REQUESTS    - total requests (overrides profile)
#   CLIENTS     - concurrent clients (overrides profile)
#   STREAMS     - max concurrent streams per client (overrides profile)
#   DURATION    - time-based mode, e.g. "30s" (overrides request count)
#   BODY_SIZE   - POST body size in bytes (default: 128)
#   WARMUP      - seconds to wait after printing config (default: 0)
#   H2C_ECHO    - path to h2c_echo binary (auto-detected if unset)
#   WORKERS     - h2c_echo worker threads (default: nproc)
#   NO_SERVER   - set to 1 to skip starting h2c_echo (use your own)

set -euo pipefail

PROFILE="${1:-moderate}"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-9000}"
BODY_SIZE="${BODY_SIZE:-128}"
WARMUP="${WARMUP:-0}"
NO_SERVER="${NO_SERVER:-0}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# --- Profile defaults ---
case "$PROFILE" in
    quick)
        DEF_REQUESTS=1000
        DEF_CLIENTS=10
        DEF_STREAMS=10
        DEF_THREADS=1
        ;;
    moderate)
        DEF_REQUESTS=100000
        DEF_CLIENTS=100
        DEF_STREAMS=100
        DEF_THREADS=4
        ;;
    heavy)
        DEF_REQUESTS=1000000
        DEF_CLIENTS=500
        DEF_STREAMS=256
        DEF_THREADS=8
        ;;
    sustained)
        DEF_REQUESTS=10000000
        DEF_CLIENTS=1000
        DEF_STREAMS=256
        DEF_THREADS=8
        WARMUP="${WARMUP:-5}"
        ;;
    *)
        echo "Unknown profile: $PROFILE"
        echo "Available: quick, moderate, heavy, sustained"
        exit 1
        ;;
esac

REQUESTS="${REQUESTS:-$DEF_REQUESTS}"
CLIENTS="${CLIENTS:-$DEF_CLIENTS}"
STREAMS="${STREAMS:-$DEF_STREAMS}"
THREADS="${THREADS:-$DEF_THREADS}"
DURATION="${DURATION:-}"

# --- Locate h2c_echo ---
if [[ "$NO_SERVER" != "1" ]]; then
    if [[ -n "${H2C_ECHO:-}" ]]; then
        : # user-provided
    elif [[ -x "$PROJECT_DIR/build-release/examples/h2c_echo" ]]; then
        H2C_ECHO="$PROJECT_DIR/build-release/examples/h2c_echo"
    elif [[ -x "$PROJECT_DIR/build/examples/h2c_echo" ]]; then
        H2C_ECHO="$PROJECT_DIR/build/examples/h2c_echo"
    else
        echo "h2c_echo not found. Build the project first or set H2C_ECHO."
        exit 1
    fi
    WORKERS="${WORKERS:-$(nproc)}"
fi

# --- Generate temp POST body ---
BODY_FILE=$(mktemp)
trap 'rm -f "$BODY_FILE"; [[ -n "${SERVER_PID:-}" ]] && kill "$SERVER_PID" 2>/dev/null || true' EXIT
dd if=/dev/urandom bs="$BODY_SIZE" count=1 of="$BODY_FILE" 2>/dev/null

# --- Start server if needed ---
SERVER_PID=""
if [[ "$NO_SERVER" != "1" ]]; then
    # Kill any existing h2c_echo on the port
    if lsof -ti :"$PORT" &>/dev/null; then
        echo "Port $PORT in use, attempting to free it..."
        kill $(lsof -ti :"$PORT") 2>/dev/null || true
        sleep 0.5
    fi

    echo "Starting h2c_echo ($WORKERS workers) on port $PORT..."
    "$H2C_ECHO" "$WORKERS" &
    SERVER_PID=$!

    # Wait for server to be ready
    for i in $(seq 1 30); do
        if nc -z "$HOST" "$PORT" 2>/dev/null; then
            break
        fi
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then
            echo "h2c_echo exited unexpectedly"
            exit 1
        fi
        sleep 0.1
    done

    if ! nc -z "$HOST" "$PORT" 2>/dev/null; then
        echo "h2c_echo failed to start within 3s"
        kill "$SERVER_PID" 2>/dev/null || true
        exit 1
    fi
    echo "Server ready (PID $SERVER_PID)"
fi

# --- Print config ---
echo ""
echo "=== Load Test: $PROFILE ==="
echo "  Target:    http://$HOST:$PORT/"
echo "  Threads:   $THREADS"
echo "  Clients:   $CLIENTS"
echo "  Streams:   $STREAMS"
if [[ -n "$DURATION" ]]; then
    echo "  Duration:  $DURATION"
else
    echo "  Requests:  $REQUESTS"
fi
echo "  Body size: $BODY_SIZE bytes"
echo ""

if [[ "$WARMUP" -gt 0 ]]; then
    echo "Warming up for ${WARMUP}s..."
    sleep "$WARMUP"
fi

# --- Build h2load command ---
H2LOAD_ARGS=(
    -t "$THREADS"
    -c "$CLIENTS"
    -m "$STREAMS"
    -d "$BODY_FILE"
    -H "content-type: application/octet-stream"
)

if [[ -n "$DURATION" ]]; then
    H2LOAD_ARGS+=(-D "$DURATION")
else
    H2LOAD_ARGS+=(-n "$REQUESTS")
fi

# --- Run ---
echo "Running h2load..."
echo ""
h2load "http://$HOST:$PORT/" "${H2LOAD_ARGS[@]}"
