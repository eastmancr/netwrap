#!/bin/sh

# Comprehensive Netwrap Test Suite
# Usage: sudo ./tests/suite.sh

NETWRAP="./netwrap"
if [ ! -x "$NETWRAP" ]; then
    echo "Building netwrap..."
    go build -o netwrap
fi

# Wait for server to be ready by tailing log file
# Usage: wait_for_log LOGFILE SEARCH_TERM [TIMEOUT_SEC]
wait_for_log() {
    logfile="$1"
    term="$2"
    timeout="${3:-5}"
    start_time=$(date +%s)

    while true; do
        if grep -q "$term" "$logfile" 2>/dev/null; then
            return 0
        fi

        current_time=$(date +%s)
        elapsed=$((current_time - start_time))
        if [ "$elapsed" -ge "$timeout" ]; then
            return 1
        fi
        sleep 0.1
    done
}

echo "=== 1. Help Test ==="
if $NETWRAP --help >/dev/null 2>&1; then echo "PASS"; else echo "FAIL"; exit 1; fi

echo "=== 2. Basic Server Test (Standard Mode) ==="
PORT=9001
rm -f test2.log
$NETWRAP -$PORT:$PORT -- python3 -u -m http.server $PORT > test2.log 2>&1 &
PID=$!

if wait_for_log "test2.log" "Serving HTTP"; then
    if curl -s localhost:$PORT >/dev/null; then
        echo "PASS"
    else
        echo "FAIL (Could not connect)"
        cat test2.log
        kill $PID 2>/dev/null
        exit 1
    fi
else
    echo "FAIL (Timeout waiting for server)"
    cat test2.log
    kill $PID 2>/dev/null
    exit 1
fi
kill $PID 2>/dev/null
wait $PID 2>/dev/null
rm test2.log

echo "=== 3. Argument Format Test (Mixed args) ==="
PORT=9013
NETNAME="netwrap_test_$$"
rm -f test3.log
$NETWRAP -n=$NETNAME -$PORT:$PORT -- python3 -u -m http.server $PORT > test3.log 2>&1 &
PID=$!

if wait_for_log "test3.log" "Serving HTTP"; then
    if curl -s localhost:$PORT >/dev/null; then
        echo "PASS"
    else
        echo "FAIL"
        cat test3.log
        kill $PID 2>/dev/null
        exit 1
    fi
else
    echo "FAIL (Timeout)"
    cat test3.log
    kill $PID 2>/dev/null
    exit 1
fi
kill $PID 2>/dev/null
wait $PID 2>/dev/null
rm test3.log
ip netns del $NETNAME 2>/dev/null || true

echo "=== 4. Script Mode Test (with Spaces) ==="
PORT=9014
NETNAME="scriptnet_$$"
cat > test.nw <<EOF
#!/usr/bin/env netwrap
n = $NETNAME
-$PORT:$PORT
python3 -u \\
  -m \\
  http.server \\
  $PORT
EOF
chmod +x test.nw
rm -f test4.log
$NETWRAP ./test.nw > test4.log 2>&1 &
PID=$!

if wait_for_log "test4.log" "Serving HTTP"; then
    if curl -s localhost:$PORT >/dev/null; then
        echo "PASS"
    else
        echo "FAIL"
        cat test4.log
        kill $PID 2>/dev/null
        rm test.nw
        exit 1
    fi
else
    echo "FAIL (Timeout)"
    cat test4.log
    kill $PID 2>/dev/null
    exit 1
fi
kill $PID 2>/dev/null
wait $PID 2>/dev/null
rm test.nw test4.log
ip netns del $NETNAME 2>/dev/null || true

echo "=== 5. Isolation Test (Negative Test) ==="
# Start server inside without mapping
PORT=9004
rm -f test5.log
$NETWRAP -- python3 -u -m http.server $PORT > test5.log 2>&1 &
PID=$!

if wait_for_log "test5.log" "Serving HTTP"; then
    # Should NOT be reachable from host
    if curl -s --connect-timeout 1 localhost:$PORT >/dev/null; then
        echo "FAIL (Server leaked to host)"
        cat test5.log
        kill $PID 2>/dev/null
        exit 1
    else
        echo "PASS (Connection failed as expected)"
    fi
else
    echo "FAIL (Timeout starting server)"
    cat test5.log
    kill $PID 2>/dev/null
    exit 1
fi
kill $PID 2>/dev/null
wait $PID 2>/dev/null
rm test5.log

echo "=== 6. Invalid Port Test ==="
# We expect "invalid client port" or "invalid protocol"
OUTPUT=$($NETWRAP -80:8x -- echo fail 2>&1)
if echo "$OUTPUT" | grep -E -q "invalid (client port|protocol)|missing protocol"; then
    echo "PASS"
else
    echo "FAIL (Output was: '$OUTPUT')"
    exit 1
fi

echo "=== 7. Environment Preservation Test ==="
export TEST_VAR="hello_world"
#shellcheck disable=SC2016
OUTPUT=$($NETWRAP -- sh -c 'echo "$TEST_VAR"')
if [ "$OUTPUT" = "hello_world" ]; then
    echo "PASS"
else
    echo "FAIL (Env var not preserved: got '$OUTPUT')"
    exit 1
fi

echo "=== 8. UDP Port Mapping Test ==="
cat > udp_server.py <<EOF
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', int(sys.argv[1])))
print('listening', flush=True) # Ensure flush for log detection
while True:
    data, addr = s.recvfrom(1024)
    s.sendto(data, addr)
EOF

PORT=9005
$NETWRAP -$PORT:$PORT/udp -- python3 -u udp_server.py $PORT > server.log 2>&1 &
PID=$!

if wait_for_log "server.log" "listening"; then
    cat > udp_client.py <<INNER_EOF
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
target = ('localhost', int(sys.argv[1]))

try:
    # Send multiple packets to test stability/concurrency
    for i in range(50):
        msg = f'udp_works_{i}'.encode('utf-8')
        s.sendto(msg, target)
        data, _ = s.recvfrom(1024)
        if data != msg:
            print(f'FAIL: mismatch on packet {i}: expected {msg}, got {data}')
            sys.exit(1)
    print('SUCCESS')
except Exception as e:
    print(f'FAIL: {e}')
INNER_EOF

    RESULT=$(python3 udp_client.py $PORT)
    if [ "$RESULT" = "SUCCESS" ]; then
        echo "PASS"
    else
        echo "FAIL ($RESULT)"
        cat server.log
        kill $PID 2>/dev/null
        exit 1
    fi
else
    echo "FAIL (Timeout waiting for UDP listener)"
    cat server.log
    kill $PID 2>/dev/null
    exit 1
fi

kill $PID 2>/dev/null
wait $PID 2>/dev/null
rm udp_server.py udp_client.py server.log

echo "=== 9. Orphan Process Check ==="
if pgrep -f "http\.server|udp_server\.py" >/dev/null; then
    echo "FAIL: Orphan processes found!"
    # shellcheck disable=SC2009
    ps -ef | grep -E "http\.server|udp_server\.py" | grep -v grep
    exit 1
else
    echo "PASS"
fi

echo "=== ALL TESTS PASSED ==="
exit 0
