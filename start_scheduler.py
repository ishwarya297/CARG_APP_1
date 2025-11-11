#!/bin/bash

# Create log directory if it doesn't exist
mkdir -p /root/Projects/logs

# Find the PID of the script
PID=$(ps aux | grep '[r]un_scheduler_loop.sh' | awk '{print $2}')

# Check if PID was found
if [ -n "$PID" ]; then
    echo "[INFO] Azure Scheduler running with PID: $PID"
else
	nohup /root/Projects/run_scheduler_loop.sh > /root/Projects/logs/daemon.log 2>&1 &
	PID=$!
	# Check if the process is running
	if pgrep -f run_scheduler_loop.sh > /dev/null; then
		echo "[SUCCESS] Azure Scheduler is running successfully"
		echo "[INFO] Azure Scheduler running with PID: $PID"
	else
		echo "[ERROR] Failed to start Azure Scheduler"
	fi
fi


