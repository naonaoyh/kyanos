#!/bin/bash
# NTRIP PCAP replay and capture end-to-end integration test for Kyanos.
# Runs three scenarios using local real PCAP playback:
#   Scenario 1: GET handshake injection -> Verifies Client Role: Rover, GGA & RTCM parsing
#   Scenario 2: SOURCE handshake injection -> Verifies Client Role: Source
#   Scenario 3: NONE (no handshake, semi-captured) -> Verifies Direct RTCM/GGA capture logic
#
# Usage:
#   ./test_ntrip_pcap_replay.sh         # Runs standard test suite with testdata-small.pcap

export PATH=/usr/local/go/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH
PROJDIR=$(pwd)
cd "$PROJDIR"

# Build kyanos binary
echo "=== Building kyanos binary ==="
make clean && make
if [ $? -ne 0 ]; then
    echo "ERROR: kyanos compilation failed"
    exit 1
fi

REPLAY_PORT=25322
LOG_DIR="./.output/kyanos_replay"
mkdir -p "$LOG_DIR"
cp ./kyanos /tmp/kyanos
chmod +x /tmp/kyanos

run_and_monitor_scenario() {
    local scenario_name=$1
    local log_file=$2
    local replay_out=$3
    local handshake=$4
    
    echo "========================================================="
    echo "=== Running Scenario: $scenario_name ==="
    rm -f "$log_file" "$replay_out"
    
    /tmp/kyanos watch ntrip --local-ports $REPLAY_PORT --debug-output --diag --diag-report --debug > "$log_file" 2>&1 &
    local kyanos_pid=$!
    
    # Wait for kyanos to be fully initialized
    for i in {1..20}; do
        if grep -q "Waiting for events" "$log_file" 2>/dev/null; then
            break
        fi
        sleep 0.5
    done
    sleep 0.5 # just a tiny extra buffer
    
    # Start python replayer in background
    python3 testdata/replay_pcap.py --pcap testdata/testdata-small.pcap --port $REPLAY_PORT --inject-handshake "$handshake" --speed 5.0 > "$replay_out" 2>&1 &
    local replay_pid=$!
    
    local start_time=$SECONDS
    local max_wait=40  # Max wait time 40s
    local last_sent=""
    local stall_count=0
    
    while true; do
        sleep 1
        local elapsed=$((SECONDS - start_time))
        
        # Parse logs
        local cur_sent=$(grep "\[replay-progress\]" "$replay_out" | tail -n 1 | sed -E 's/.*sent: ([0-9]+)\/.*/\1/' || echo "0")
        if [ -z "$cur_sent" ]; then cur_sent="0"; fi
        
        local kyanos_events=$(wc -l < "$log_file" 2>/dev/null || echo "0")
        
        echo -ne "[$elapsed s] Replayer sent pkts: $cur_sent | Kyanos log lines: $kyanos_events \r"
        
        if ! kill -0 $replay_pid 2>/dev/null; then
            echo -e "\n[$elapsed s] Replayer exited."
            break
        fi
        
        if [ $elapsed -ge $max_wait ]; then
            echo -e "\n[$elapsed s] TIMEOUT reached."
            break
        fi
        
        if [ "$cur_sent" == "$last_sent" ] && [ "$cur_sent" != "0" ]; then
            stall_count=$((stall_count + 1))
        else
            stall_count=0
        fi
        
        last_sent=$cur_sent
        
        if [ $stall_count -ge 5 ]; then
            echo -e "\n[WARN] Progress stalled for 5 seconds. Checking for blockages..."
            grep "\[WARN\] Socket send blocked" "$replay_out" || echo "No python send blocks detected."
            break
        fi
        
        # Partial pass threshold for scenario 3 (Semi-captured)
        if [ "$handshake" == "NONE" ]; then
            if grep -q "Client Role: Rover" "$log_file" && [ "$cur_sent" -gt 1500 ]; then
                echo -e "\n[$elapsed s] PARTIAL PASS THRESHOLD MET: Detected Rover role and 1500+ pkts sent in semi-captured mode."
                break
            fi
        fi
    done
    
    echo "=== Stop Kyanos and Python ==="
    kill -KILL $replay_pid 2>/dev/null || true
    kill -INT $kyanos_pid 2>/dev/null || true
    sleep 2
    kill -KILL $kyanos_pid 2>/dev/null || true
    wait $kyanos_pid 2>/dev/null || true
}

LOG_1="$LOG_DIR/kyanos_replay_rover.log"
REPLAY_OUT_1="$LOG_DIR/replay_rover.log"
run_and_monitor_scenario "Scenario 1 (GET Rover)" "$LOG_1" "$REPLAY_OUT_1" "GET"

LOG_2="$LOG_DIR/kyanos_replay_source.log"
REPLAY_OUT_2="$LOG_DIR/replay_source.log"
run_and_monitor_scenario "Scenario 2 (SOURCE Source)" "$LOG_2" "$REPLAY_OUT_2" "SOURCE"

LOG_3="$LOG_DIR/kyanos_replay_semi.log"
REPLAY_OUT_3="$LOG_DIR/replay_semi.log"
run_and_monitor_scenario "Scenario 3 (NONE Semi-captured)" "$LOG_3" "$REPLAY_OUT_3" "NONE"

echo "=========================================="
echo "  VERIFICATION RESULTS"
echo "=========================================="
STATUS=0

# Helper function to verify replayer log correctness and continuous output
verify_replayer_log() {
    local replay_log=$1
    local name=$2
    local handshake=$3
    echo -n "$name Replayer continuous output check: "
    if ! grep -q "\[replay-progress\]" "$replay_log"; then
        echo "FAIL (No progress updates, playback was not continuous)"
        return 1
    fi
    # If not NONE, we expect summary to eventually appear, OR it could have stalled.
    if [ "$handshake" != "NONE" ]; then
        if ! grep -q "\[replay-summary\] Stats:" "$replay_log"; then
            if grep -q "Socket send blocked" "$replay_log"; then
                echo "FAIL (Replayer stalled due to Send Blocks!)"
            else
                echo "FAIL (Replayer did not complete successfully)"
            fi
            return 1
        fi
    fi
    echo "PASS"
    return 0
}

# 1. Verify Replayer Logs
verify_replayer_log "$REPLAY_OUT_1" "Scenario 1 (Rover)" "GET" || STATUS=1
verify_replayer_log "$REPLAY_OUT_2" "Scenario 2 (Source)" "SOURCE" || STATUS=1
verify_replayer_log "$REPLAY_OUT_3" "Scenario 3 (Semi-captured)" "NONE" || STATUS=1

# 2. Verify Roles
echo -n "Scenario 1 (Rover) Client Role check: "
if grep -q "Client Role: Rover" "$LOG_1"; then
    echo "PASS"
else
    echo "FAIL (Cannot find 'Client Role: Rover' in log)"
    STATUS=1
fi

echo -n "Scenario 2 (Source) Client Role check: "
if grep -q "Client Role: Source" "$LOG_2"; then
    echo "PASS"
else
    echo "FAIL (Cannot find 'Client Role: Source' in log)"
    STATUS=1
fi

echo -n "Scenario 3 (Semi-captured) Client Role check: "
if grep -q "Client Role: Rover" "$LOG_3"; then
    echo "PASS"
else
    echo "FAIL (Cannot identify 'Client Role: Rover' via frequent GGA/RTCM)"
    STATUS=1
fi

echo "=========================================="
if [ $STATUS -eq 0 ]; then
    echo "=== PCAP REPLAY TEST COMPLETE: ALL PASS ==="
else
    echo "=== PCAP REPLAY TEST COMPLETE: SOME SCENARIOS FAILED ==="
    echo "--- Debug details from Scenario 3 Kyanos output ---"
    cat "$LOG_3" | grep -A 30 "NTRIP Session Diagnostic Report" || true
fi

exit $STATUS
