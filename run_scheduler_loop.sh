#!/bin/bash
while true; do
    /root/Projects/automatic_scheduler.sh
    sleep 3600  # Wait 1 Hour before next run
done

# ======================================================================================
# In order to start the azure scheduler start the following lines
#
# $> nohup /root/Projects/run_scheduler_loop.sh > /root/Projects/logs/daemon.log 2>&1 &
# $> ps aux | grep run_scheduler_loop.sh
# ======================================================================================

# ======================================================================================
# In order to stop the azure scheduler start the following lines
#
# $> ps aux | grep run_scheduler_loop.sh
# $> kill -9 <Proccess_ID of run_scheduler_loop.sh>
# ======================================================================================
