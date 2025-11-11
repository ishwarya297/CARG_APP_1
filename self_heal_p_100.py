# pip install azure-identity azure-mgmt-storage

from azure.identity import ClientSecretCredential
from azure.mgmt.storage import StorageManagementClient

# Set up your subscription ID and resource details
subscription_id = '1128ac1e-2822-4693-b31a-570f9c739cbb'
tenant_id = '6efbfbdd-57af-4e28-9f2c-9b75f72a6ffe'
client_id = '729dc29d-edb5-4848-9133-bd047f2c8445'
client_secret = <secret_value>
resource_group_name = 'Soteria-Test-Env'
storage_account_name = 'selfhealtestcontainer'

# Authenticate using DefaultAzureCredential
credential = ClientSecretCredential(tenant_id, client_id, client_secret)

# Initialize the Storage Management client
storage_client = StorageManagementClient(credential, subscription_id)

def set_storage_account_network_access_to_deny():
    # Get the current network rule set
    storage_account = storage_client.storage_accounts.get_properties(resource_group_name, storage_account_name)
    network_rule_set = storage_account.network_rule_set

    # Check if the default action is already set to "Deny"
    if network_rule_set.default_action == "Deny":
        print(f"Default network access for storage account '{storage_account_name}' is already set to 'Deny'.")
    else:
        # Update the network rule set to set default action to "Deny"
        network_rule_set.default_action = "Deny"
        
        # Apply the updated network rule set
        storage_client.storage_accounts.update(
            resource_group_name,
            storage_account_name,
            {
                'network_rule_set': network_rule_set
            }
        )
        print(f"Default network access for storage account '{storage_account_name}' has been set to 'Deny'.")

if __name__ == "__main__":
    set_storage_account_network_access_to_deny()
