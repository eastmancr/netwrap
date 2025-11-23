#!/bin/sh

# Ensure we are root
if [ "$(id -u)" -ne 0 ]; then
    sudo -v || exit 1
    exec sudo "$0" "$@"
fi

# POINT TO GO BINARY
NETWRAP="./netwrap"
if [ ! -x "$NETWRAP" ]; then
    echo "Error: $NETWRAP not found or not executable."
    exit 1
fi

BASE_PORT=4001
PROXY_PORT=5001
INPUT_FILE="/dev/zero"
SIZE_MB=1000

echo "--- Netwrap Performance Benchmark ---"
echo "Transfer Size: ${SIZE_MB}MB"

run_benchmark() {
    mode="$1"
    port="$2"

    start=$(date +%s.%N)

    dd if="$INPUT_FILE" bs=1M count=$SIZE_MB 2>/dev/null | socat -u STDIO TCP:localhost:"$port"

    end=$(date +%s.%N)

    duration=$(echo "$end $start" | awk '{print $1 - $2}')
    if [ "$(echo "$duration < 0.01" | awk '{print ($1 < 0.01)}')" -eq 1 ]; then
         throughput="INF"
    else
         throughput=$(echo "$SIZE_MB $duration" | awk '{printf "%.2f", $1 / $2}')
    fi

    echo "Mode: $mode"
    echo "Time: ${duration}s"
    echo "Speed: ${throughput} MB/s"
    echo "-------------------------------------"
}

# 1. Native Benchmark
echo "Setting up Native Test (Host -> Host)..."
socat -u TCP-LISTEN:$BASE_PORT,reuseaddr,fork OPEN:/dev/null &
SERVER_PID=$!
sleep 1

run_benchmark "Native" $BASE_PORT

kill $SERVER_PID
wait $SERVER_PID 2>/dev/null

# 2. Netwrap Benchmark
echo "Setting up Netwrap Test (Host -> Proxy -> Container)..."
$NETWRAP -$PROXY_PORT:$BASE_PORT -- socat -u TCP-LISTEN:$BASE_PORT,reuseaddr,fork OPEN:/dev/null &
NW_PID=$!
sleep 2

run_benchmark "Netwrap" $PROXY_PORT

kill $NW_PID
wait $NW_PID 2>/dev/null

echo "Done."
