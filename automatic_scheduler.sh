#!/bin/bash

LOCKFILE="/tmp/azure_cron.lock"

# Prevent overlapping runs
if [ -e "$LOCKFILE" ]; then
    echo "Another instance is already running. Exiting."
    exit 1
fi

touch "$LOCKFILE"
trap "rm -f $LOCKFILE" EXIT

# Activate virtual environment
source /root/Projects/ccs/bin/activate

# Ensure log directory exists
mkdir -p /root/Projects/logs

# Get current timestamp in YYYYMMDD_HHMMSS format
timestamp=$(date +"%Y%m%d_%H%M%S")

# Create log file names with timestamp
log1="/root/Projects/logs/azure_native_scheduler_${timestamp}.log"
log2="/root/Projects/logs/carg_alerts_${timestamp}.log"

python3 /root/Projects/azure_native_scheduler.py > "$log1" 2>&1

if [ $? -eq 0 ]; then
    echo "azure_native_scheduler.py executed successfully. Running carg_alerts.py..." | tee -a "$log1"
    python3 "/root/Projects/carg_alerts.py" > "$log2" 2>&1
    echo "carg_alerts.py executed successfully." | tee -a "$log2"
else
    echo "azure_native_scheduler.py failed. Check $log1 for details. carg_alerts.py will not run."
    exit 1
fi
