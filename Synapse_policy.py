from datetime import date
from datetime import datetime

t=datetime.now()
x = t.replace(microsecond=0)
Time = int(datetime.timestamp(x))

Resource="microsoft.synapse"
Assets = "Workspaces"

def output(Policyname,location,asset_id,Status,Description,Recommendation,subscription_id):
    if Status.upper() == "ACTIVE": 
          
        json_obj={
                    "Source" : "Native service - Azure",
                    "PolicyName": Policyname,
                    "CloudType": "Azure",
                    "CloudAccountId": subscription_id,
                    "ResourceRegion": location,
                    "Resource": Resource,
                    "Assets": Assets,
                    "AssetId": asset_id,
                    "Status": Status,
                    "OpenedAt" : Time,
                    "ClosedAt": "Nil",
                    "Description": Description,
                    "Recommendation": Recommendation
                }
    else:
        json_obj={
                    "Source" : "Native service - Azure",
                    "PolicyName": Policyname,
                    "CloudType": "Azure",
                    "CloudAccountId": subscription_id,
                    "ResourceRegion": location,
                    "Resource": Resource,
                    "Assets": Assets,
                    "AssetId": asset_id,
                    "Status": Status,
                    "OpenedAt" : "Nil",
                    "ClosedAt": Time,
                    "Description": Description,
                    "Recommendation": Recommendation
                }
    return json_obj

def p127(asset_id,location,Status,subscription_id):
    Policyname = "Ensure Azure Synapse Analytics workspaces have double encryption enabled with customer managed keys (CMK)"
    Description = "This policy identifies synapse analytics workspaces that do not have double encryption enforced with customer-managed keys. CMKs give an additional layer of security and are a crucial part of comprehensive encryption at rest solution."  
    Recommendation  = "Encryption setting for synapse analytics cannot be changed after the creation of the workspace. Take a snapshot and recreate the workspace with double encryption enforced." 
    return output(Policyname,location,asset_id,Status,Description,Recommendation,subscription_id)

def p127_send(non_compliant, compliant):
    print("Sending non-compliant data for Policy 127:")
    print(non_compliant)
    print(compliant)

def p143(asset_id,location,Status,subscription_id):
    Policyname = "Ensure Azure Synapse Analytics workspace does not have overly permissible firewall rules"
    Description = "This policy audits synapse analytics workspaces that have firewall rules with starting IP addresses as '0.0.0.0'"  
    Recommendation  = "Navigate to the non-compliant synapse analytics workspace. If the workspace does not need to allow all IP addresses, then navigate to the firewalls section in the workspace and delete the non-compliant rules" 
    return output(Policyname,location,asset_id,Status,Description,Recommendation,subscription_id)

def p143_send(non_compliant, compliant):
    print("Sending non-compliant data for Policy 143:")
    print(non_compliant)
    print(compliant)

def p163(asset_id,location,Status,subscription_id):
    Policyname = "Ensure Azure Synapse Analytics workspace is not publicly accessible "
    Description = "This policy identifies synapse analytics workspaces that have public network access enabled."  
    Recommendation  = "Navigate to the non-compliant synapse analytics workspace and add a private endpoint." 
    return output(Policyname,location,asset_id,Status,Description,Recommendation,subscription_id)

def p163_send(non_compliant, compliant):
    print("Sending non-compliant data for Policy 163:")
    print(non_compliant)
    print(compliant)

def p344(asset_id,location,Status,subscription_id):
    Policyname = "Vulnerability assessment should be enabled on your Synapse workspaces"
    Description = "Discover, track, and remediate potential vulnerabilities by configuring recurring SQL vulnerability assessment scans on your Synapse workspaces."
    Recommendation  = "Take the following steps to configure the vulnerability assessment: 1. In the Azure portal, open the specific resource in Azure SQL Database, SQL Managed Instance Database, or Azure Synapse. 2. Under the Security heading, select Defender for Cloud. 3. Select Configure on the link to open the Microsoft Defender for SQL settings pane for either the entire server or managed instance. 4. In the Server settings page, define the Microsoft Defender for SQL settings: a. Configure a storage account where your scan results for all databases on the server or managed instance will be stored. For information about storage accounts, see About Azure storage accounts. b. To configure vulnerability assessments to automatically run weekly scans to detect security misconfigurations, set Periodic recurring scans to On. The results are sent to the email addresses you provide in Send scan reports to. You can also send email notification to admins and subscription owners by enabling Also send email notification to admins and subscription owners. 5. SQL vulnerability assessment scans can also be run on-demand: a. From the resource's Defender for Cloud page, select View additional findings in Vulnerability Assessment to access the scan results from previous scans. b. To run an on-demand scan to scan your database for vulnerabilities, select Scan from the toolbar." 
    return output(Policyname,location,asset_id,Status,Description,Recommendation,subscription_id)

def p344_send(non_compliant, compliant):
    print("Sending non-compliant data for Policy 344:")
    print(non_compliant)
    print(compliant)

def p345(asset_id,location,Status,subscription_id):
    Policyname = "Azure Synapse workspaces should allow outbound data traffic only to approved targets"
    Description = "Increase security of your Synapse workspace by allowing outbound data traffic only to approved targets. This helps prevention against data exfiltration by validating the target before sending data."
    Recommendation  = "While creating the synapse workspace, in the networking tab, after you choose to associate a Managed workspace Virtual Network with your workspace, you can protect against data exfiltration by allowing outbound connectivity from the Managed workspace Virtual Network only to approved targets using Managed private endpoints. Select Yes to limit outbound traffic from the Managed workspace Virtual Network to targets through Managed private endpoints. You cannot change the workspace configuration for managed virtual network and data exfiltration protection after the workspace is created." 
    return output(Policyname,location,asset_id,Status,Description,Recommendation,subscription_id)

def p345_send(non_compliant, compliant):
    print("Sending non-compliant data for Policy 345:")
    print(non_compliant)
    print(compliant)

def p346(asset_id,location,Status,subscription_id):
    Policyname = "Managed workspace virtual network on Azure Synapse workspaces should be enabled"
    Description = "Enabling a managed workspace virtual network ensures that your workspace is network isolated from other workspaces. Data integration and Spark resources deployed in this virtual network also provides user level isolation for Spark activities."
    Recommendation  = "To create an Azure Synapse workspace that has a Managed workspace Virtual Network associated with it, select the Networking tab while creating a synapse workspace in Azure portal and check the Enable managed virtual network checkbox. If you leave the checkbox unchecked, then your workspace won't have a Virtual Network associated with it. You cannot change this workspace configuration after the workspace is created." 
    return output(Policyname,location,asset_id,Status,Description,Recommendation,subscription_id)

def p346_send(non_compliant, compliant):
    print("Sending non-compliant data for Policy 346:")
    print(non_compliant)
    print(compliant)

def p347(asset_id,location,Status,subscription_id):
    Policyname = "Auditing on Synapse workspace should be enabled"
    Description = "Auditing on your Synapse workspace should be enabled to track database activities across all databases on the dedicated SQL pools and save them in an audit log."
    Recommendation  = "Auditing can be enabled at the workspace level, which will cover all databases on the workspace automatically, or at the individual database level. First, navigate to your Synapse Analytics Workspace or dedicated SQL pool in the Azure Portal. My screenshots will show the configuration from the dedicated SQL pool, but the same setting can be found under the label of Azure SQL Auditing at the workspace level. From here, select Auditing from the Security section. Next, toggle the Enable Azure SQL Auditing to the on position. Next, check the boxes for the locations where you would like the log to be written, in this example we are going to focus on Log Analytics. Select a log analytics workspace to which the data will be written. Click Save once complete." 
    return output(Policyname,location,asset_id,Status,Description,Recommendation,subscription_id)

def p347_send(non_compliant, compliant):
    print("Sending non-compliant data for Policy 347:")
    print(non_compliant)
    print(compliant)

def p348(asset_id,location,Status,subscription_id):
    Policyname = "Azure Synapse workspaces should use private link"
    Description = "Azure Private Link lets you connect your virtual network to Azure services without a public IP address at the source or destination. The Private Link platform handles the connectivity between the consumer and services over the Azure backbone network. By mapping private endpoints to Azure Synapse workspace, data leakage risks are reduced. Learn more about private links at: https://docs.microsoft.com/azure/synapse-analytics/security/how-to-connect-to-workspace-with-private-links."
    Recommendation  = "1. Select Private endpoint connection under Security. 2. On the next screen select + Private endpoint. 3. Under the Basics tab in the Create a private endpoint window, choose your Subscription and Resource Group. Give a Name to the private endpoint that you want to create. Select the Region where you want the private endpoint created. 4. Private endpoints are created in a subnet. The subscription, resource group, and region selected filter the private endpoint subnets. Select Next: Resource > when done. 5. Select Connect to an Azure resource in my directory in the Resource tab. Select the Subscription that contains your Azure Synapse workspace. The Resource type for creating private endpoints to an Azure Synapse workspace is Microsoft.Synapse/workspaces. 6.  Select your Azure Synapse workspace as the Resource. Every Azure Synapse workspace has three Target sub-resource that you can create a private endpoint to: Sql, SqlOnDemand, and Dev. Sql is for SQL query execution in SQL pool. SqlOnDemand is for SQL built-in query execution. Dev is for accessing everything else inside Azure Synapse Analytics Studio workspaces. 7. Select Next: Configuration> to advance to the next part of the setup. 8. In the Configuration tab, select the Virtual network and the Subnet in which the private endpoint should be created. You also need to create a DNS record that maps to the private endpoint. 9. Select Yes for Integrate with private DNS zone to integrate your private endpoint with a private DNS zone. If you don't have a private DNS zone associated with your Microsoft Azure Virtual Network, then a new private DNS zone is created. Select Review + create when done. 10. When the deployment is complete, open your Azure Synapse workspace in Azure portal and select Private endpoint connections. The new private endpoint and private endpoint connection name associated to the private endpoint are shown." 
    return output(Policyname,location,asset_id,Status,Description,Recommendation,subscription_id)

def p348_send(non_compliant, compliant):
    print("Sending non-compliant data for Policy 348:")
    print(non_compliant)
    print(compliant)

def p349(asset_id,location,Status,subscription_id):
    Policyname = "IP firewall rules on Azure Synapse workspaces should be removed"
    Description = "Removing all IP firewall rules improves security by ensuring your Azure Synapse workspace can only be accessed from a private endpoint. This configuration audits creation of firewall rules that allow public network access on the workspace."
    Recommendation  = "You can delete IP firewall rules to a Synapse workspace by following the given steps: 1. Select Networking under Security from Azure portal. To delete IP firewall rule, click on the three dots infront of the IP rule and select delete. Delete all the rules. Select Save when done." 
    return output(Policyname,location,asset_id,Status,Description,Recommendation,subscription_id)

def p349_send(non_compliant, compliant):
    print("Sending non-compliant data for Policy 349:")
    print(non_compliant)
    print(compliant)

def p413(asset_id,location,Status,subscription_id):
    Policyname = "Ensure that a 'Diagnostics Setting' exists for Synapse workspaces"
    Description = "Enable Diagnostic settings for exporting activity logs. Diagnostic setting are available for each individual resources within a subscription. Settings should be configured for all appropriate resources for your environment."  
    Recommendation  = "From Azure Console 1. Click on the resource that has a diagnostic status of disabled 2. Select Add Diagnostic Settings 3. Enter a Diagnostic setting name 4. Select the appropriate log, metric, and destination. (This may be Log Analytics/Storage account or Event Hub) 5. Click save Repeat these step for all resources as needed. Default Value: By default, diagnostic setting is not set."  
    return output(Policyname,location,asset_id,Status,Description,Recommendation,subscription_id)

def p413_send(non_compliant, compliant):
    print("Sending non-compliant data for Policy 413:")
    print(non_compliant)
    print(compliant)

def p478(asset_id,location,Status,subscription_id):
    Policyname = "Ensure that Resource Locks are set for synapse analytics"
    Description = (
        "Checks if Resource Locks are set for Azure Synapse Analytics. The rule is NON-COMPLIANT if Resource Locks are not configured to prevent deletion of or modifications to Azure Synapse Analytics."
    )
    Recommendation = (
        '''From Azure Console
        1. Navigate to the specific Azure Resource or Resource Group
        2. For each of the mission critical resource, click on Locks
        3. Click Add
        4. Give the lock a name and a description, then select the type, CanNotDelete or ReadOnly as appropriate
        Using Azure Command Line Interface 2.0
        To lock a resource, provide the name of the resource, its resource type, and its resource group name.
        az lock create --name <LockName> --lock-type <CanNotDelete/Read-only> -resource-group <resourceGroupName> --resource-name <resourceName> --resourcetype <resourceType>
        Default Value:
        By default, no locks are set.''')
    return output(Policyname,location,asset_id,Status,Description,Recommendation,subscription_id)

def p478_send(non_compliant, compliant):
    print("Sending non-compliant data for Policy 478:")
    print(non_compliant)
    print(compliant)
