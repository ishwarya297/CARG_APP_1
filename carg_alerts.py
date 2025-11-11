import subprocess

def run_file(filename):
    print(f"Running {filename} ...")
    try:
        result = subprocess.run(['python', filename], capture_output=True, text=True)
        print(f"Output of {filename}:\n{result.stdout}")
        if result.stderr:
            print(f"Errors in {filename}:\n{result.stderr}")
    except Exception as e:
        print(f"Error running {filename}: {e}")
    print("-" * 80)

if __name__ == "__main__":

    run_file('/root/Projects/CARG/Azure_CARG_Services/Storage Accounts/StorageAccounts_exec.py')
    run_file('/root/Projects/CARG/Azure_CARG_Services/Network Watcher/NW_exec.py')
    run_file('/root/Projects/CARG/Azure_CARG_Services/API_Management_Services/API_exec.py')
    run_file("/root/Projects/CARG/Azure_CARG_Services/Virtual_Networks/Virtual_Network/Vnet_exec.py")
    run_file('/root/Projects/CARG/Azure_CARG_Services/Load_Balancers/LB_exec.py')
    run_file('/root/Projects/CARG/Azure_CARG_Services/Network_Interface/NI_exec.py')
    run_file('/root/Projects/CARG/Azure_CARG_Services/SQL_Database/SQL_Database_exec.py')
    run_file('/root/Projects/CARG/Azure_CARG_Services/Key_Vault/KV_exec.py')
    run_file('/root/Projects/CARG/Azure_CARG_Services/Signal_R/SignalR_exec.py')
    run_file('/root/Projects/CARG/Azure_CARG_Services/Azure_Database_for_MySQL_flexi_servers/MySQL_exec.py')
    run_file('/root/Projects/CARG/Azure_CARG_Services/Azure_Database_for_PostgreSQL_flexible_servers/flexi_server_exec.py')
    run_file('/root/Projects/CARG/Azure_CARG_Services/Service_Bus/Service_Bus_exec.py')
    run_file('/root/Projects/CARG/Azure_CARG_Services/Azure_Cache_for_Redis/Azure_Cache_for_Redis_exec.py')
    run_file('/root/Projects/CARG/Azure_CARG_Services/Disks_/Disks_exec.py')
    run_file('/root/Projects/CARG/Azure_CARG_Services/Event_Hub/Hub_exec.py')
    run_file('/root/Projects/CARG/Azure_CARG_Services/Virtual_Machines/VM_exec.py')
     

    run_file('/root/Projects/CARG/Azure_CARG_Services/App_Services/Web_App/Web_App_exec.py')
