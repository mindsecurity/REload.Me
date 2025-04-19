#!/bin/bash
# sandbox/trace.sh
# Script to trace binary execution with strace, ltrace, and tcpdump

BINARY="$1"
OUTPUT_DIR="/app/output"
mkdir -p "$OUTPUT_DIR"

# Start tcpdump in background to capture network activity
tcpdump -i any -w "$OUTPUT_DIR/network.pcap" &
TCPDUMP_PID=$!

# Start strace to monitor syscalls
strace -o "$OUTPUT_DIR/strace.log" -f -tt -T -s 256 -e trace=all "$BINARY" &
STRACE_PID=$!

# Start ltrace to monitor library calls
ltrace -o "$OUTPUT_DIR/ltrace.log" -f -S "$BINARY" &
LTRACE_PID=$!

# Run the binary
"$BINARY" > "$OUTPUT_DIR/stdout.log" 2> "$OUTPUT_DIR/stderr.log"

# Wait for monitoring processes
kill $TCPDUMP_PID $STRACE_PID $LTRACE_PID 2>/dev/null

# Parse and format output
echo "=== SYSCALL TRACE ===" > "$OUTPUT_DIR/analysis.txt"
cat "$OUTPUT_DIR/strace.log" >> "$OUTPUT_DIR/analysis.txt"
echo -e "\n=== LIBRARY CALLS ===" >> "$OUTPUT_DIR/analysis.txt"
cat "$OUTPUT_DIR/ltrace.log" >> "$OUTPUT_DIR/analysis.txt"
echo -e "\n=== NETWORK ACTIVITY ===" >> "$OUTPUT_DIR/analysis.txt"
tcpdump -r "$OUTPUT_DIR/network.pcap" -n >> "$OUTPUT_DIR/analysis.txt"

# Output to stdout for container logs
cat "$OUTPUT_DIR/analysis.txt"