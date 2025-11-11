# Stop the scheduler
#!/bin/bash
# This script stops the scheduler service

# Find the PID of the script
PID=$(ps aux | grep '[r]un_scheduler_loop.sh' | awk '{print $2}')

# Check if PID was found
if [ -n "$PID" ]; then
    echo "[INFO] Azure Scheduler running with PID: $PID"
    echo "[INFO] Stopping the Azure Scheduler process..."
    kill -9 "$PID"

    # Optional: check if kill succeeded
    if [ $? -eq 0 ]; then
        echo "[SUCCESS] Process $PID killed."
    else
        echo "[ERROR] Failed to kill process $PID."
    fi
else
    echo "[INFO] Azure Scheduler not running, nothing to stop."
fi
