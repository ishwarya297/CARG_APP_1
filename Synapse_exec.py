print("executing Azure Synapse Analytics checks")
from dotenv import load_dotenv
import os
from azure.identity import ClientSecretCredential  
from botocore.exceptions import ClientError
import base64
import psycopg2
import boto3
import requests
import json
import sys
import argparse
import logging
from Synapse_policy import *

load_dotenv()

# Add the correct path to sys.path
base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if base_dir not in sys.path:
    sys.path.append(base_dir)

print("Added to sys.path:", base_dir)

from DatabaseLayer import (
    get_azure_parameters,
    insert_noncompliance_results_to_db,
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

non_status = "ACTIVE"
com_status = "INACTIVE"

def get_secret():
    secret_name = os.environ['SECRET_NAME']
    region_name = os.environ['REGION_NAME']
    secretsmanager_client = boto3.client(
        service_name='secretsmanager',
        region_name=region_name
    )
    try:
        get_secret_value_response = secretsmanager_client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        raise e
    return get_secret_value_response['SecretString']

def base64decoder(encoded_string):
    try:
        decoded_bytes = base64.b64decode(encoded_string)
        decoded_string = decoded_bytes.decode('utf-8')
        return decoded_string
    except Exception as e:
        print(f"Error decoding base64 string: {e}")
        return None

def get_db_connection():
    secret = json.loads(get_secret())
    conn = psycopg2.connect(
        host=secret['proxy'],
        port=secret['port'],
        database=secret['dbname'],
        user=secret['username'],
        password=secret['password']
    )
    return conn

def headers(credential):
    return {"Authorization": f"Bearer {credential.get_token('https://management.azure.com/.default').token}"}

def db_data_collection():
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute(
            "SELECT clientid, clientsecret, tenantid, subscriptionid FROM ccsadminnew.ccscloudaccountmaster WHERE cloudtype_id=2;")
        rows = cursor.fetchall()
        result = []
        if not rows:
            cursor.close()
            connection.close()
            return []
        for row in rows:
            tenant_id_encoded = row[2]
            tenant_id = base64decoder(
                tenant_id_encoded) if tenant_id_encoded else None
            print("Raw tenant_id from db:", tenant_id_encoded)
            if not tenant_id:
                print("Tenant ID is missing, skipping this row.")
                continue
            client_id_encoded = row[0]
            client_id = base64decoder(
                client_id_encoded) if client_id_encoded else None
            if not client_id or not tenant_id:
                print("Client ID or Tenant ID is missing, skipping this row.")
                continue
            client_secret_encoded = row[1]
            client_secret = base64decoder(
                client_secret_encoded) if client_secret_encoded else None
            if not client_secret:
                print("Client Secret is missing, skipping this row.")
                continue
            subscription_id = row[3]
            credential = ClientSecretCredential(
                tenant_id, client_id, client_secret)
            head = headers(credential)
            result.append([subscription_id, head, credential])
        cursor.close()
        connection.close()
        return result
    except Exception as e:
        print(f"Error in calling functions: {e}")
        return []

def authentication(url,headers,payload):
    response = requests.request("POST", url, headers=headers, data = payload)
    return json.loads(response.text).get('access_token')

def list_subscription(head):
    url1 ="https://management.azure.com/subscriptions?api-version=2020-01-01"
    r = requests.request("GET", url1, headers=head)
    return json.loads(r.text).get('value',[]) 

def list_synapses(subscription_id,head):
    url ="https://management.azure.com/subscriptions/"+subscription_id+"/providers/Microsoft.Synapse/workspaces?api-version=2021-03-01"
    r = requests.request("GET", url, headers=head)
    return json.loads(r.text).get('value',[])

def list_firewall_rules(name,resourceGroupName,subscription_id,head):
    url ="https://management.azure.com/subscriptions/"+subscription_id+"/resourceGroups/"+resourceGroupName+"/providers/Microsoft.Synapse/workspaces/"+name+"/firewallRules?api-version=2021-03-01"
    r = requests.request("GET", url, headers=head)
    return json.loads(r.text).get('value',[])

def list_vulnerabilityAssessment(name,resourceGroupName,subscription_id,head):
    url ="https://management.azure.com/subscriptions/"+subscription_id+"/resourceGroups/"+resourceGroupName+"/providers/Microsoft.Synapse/workspaces/"+name+"/vulnerabilityAssessments?api-version=2021-06-01"
    r = requests.request("GET", url, headers=head)
    return json.loads(r.text).get('value',[])

def list_auditingSetting(name,resourceGroupName,subscription_id,head):
    url ="https://management.azure.com/subscriptions/"+subscription_id+"/resourceGroups/"+resourceGroupName+"/providers/Microsoft.Synapse/workspaces/"+name+"/auditingSettings?api-version=2021-06-01"
    r = requests.request("GET", url, headers=head)
    return json.loads(r.text).get('value',[])

def diagnostics(resourceId,head):
    diagnostic_url="https://management.azure.com/"+resourceId+"/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview"
    req = requests.request("GET", diagnostic_url, headers=head)
    return json.loads(req.text).get('value',[])

def list_resource_locks(subscription_id, resource_group, workspace_name, head):
    url = (
        f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
        f"/providers/Microsoft.Synapse/workspaces/{workspace_name}/providers/Microsoft.Authorization/locks"
    )
    params = {"api-version": "2016-09-01"}
    r = requests.get(url, headers=head, params=params)
    return json.loads(r.text).get('value', [])

def main():
    results = db_data_collection()
    print(results)
    for result in results:
        subscription_id = result[0]
        credential = result[2]
        head = headers(credential)
        non127, non143, non163, non344, non345, non346, non347, non348, non349, non413, non478 = ([] for i in range(11))
        com127, com143, com163, com344, com345, com346, com347, com348, com349, com413, com478 = ([] for i in range(11))

        synapses = list_synapses(subscription_id, head)
        Com344 = []
        count = 0

        for synapse in synapses:
            resourceId = synapse['id']
            name = synapse.get('name')
            location = synapse.get('location')
            resourceGroupName = synapse.get('id').split('/')[4]

            vulassess = list_vulnerabilityAssessment(name, resourceGroupName, subscription_id, head)
            if len(vulassess) != 0:
                for assess in vulassess:
                    recurringScan = assess['properties']['recurringScans']['isEnabled']
                    if recurringScan == True:
                        Com344.append(name)

            Com344 = list(set(Com344))
            if name in Com344:
                com344.append(p344(name, location, com_status, subscription_id))
            else:
                non344.append(p344(name, location, non_status, subscription_id))

            if 'managedVirtualNetwork' in synapse['properties']:
                managedVirtualNetwork = synapse['properties']['managedVirtualNetwork']
                if managedVirtualNetwork == 'default':
                    com346.append(p346(name, location, com_status, subscription_id))
                else:
                    non346.append(p346(name, location, non_status, subscription_id))
            else:
                non346.append(p346(name, location, non_status, subscription_id))

            AuditSett = list_auditingSetting(name, resourceGroupName, subscription_id, head)
            if len(AuditSett) != 0:
                for auditset in AuditSett:
                    state = auditset['properties']['state']
                    if state == "Disabled":
                        non347.append(p347(name, location, non_status, subscription_id))
                    else:
                        com347.append(p347(name, location, com_status, subscription_id))
            else:
                non347.append(p347(name, location, non_status, subscription_id))

            privateEndpointconnection = synapse['properties']['privateEndpointConnections']
            if len(privateEndpointconnection) != 0:
                for conn in privateEndpointconnection:
                    status = conn['properties']['privateLinkServiceConnectionState']['status']
                    if status == "Approved":
                        count = count + 1
            if count == 0:
                non348.append(p348(name, location, non_status, subscription_id))
            else:
                com348.append(p348(name, location, com_status, subscription_id))

            if 'managedVirtualNetworkSettings' in synapse['properties']:
                preventDataExfiltration = synapse['properties']['managedVirtualNetworkSettings']['preventDataExfiltration']
                if preventDataExfiltration == False:
                    non345.append(p345(name, location, non_status, subscription_id))
                else:
                    com345.append(p345(name, location, com_status, subscription_id))
            else:
                non345.append(p345(name, location, non_status, subscription_id))

            # policy 143, 349
            ip_rules = list_firewall_rules(name, resourceGroupName, subscription_id, head)
            if len(ip_rules) != 0:
                non349.append(p349(name, location, non_status, subscription_id))
            else:
                com349.append(p349(name, location, com_status, subscription_id))

            ipcount = 0
            for rule in ip_rules:
                if rule.get('properties').get('startIpAddress') == "0.0.0.0":
                    ipcount = ipcount + 1

            if ipcount > 0:
                non143.append(p143(name, location, non_status, subscription_id))
            else:
                com143.append(p143(name, location, com_status, subscription_id))

            # policy 127
            encryption = synapse.get('properties').get('encryption').get('doubleEncryptionEnabled')
            if encryption is False:
                non127.append(p127(name, location, non_status, subscription_id))
            else:
                com127.append(p127(name, location, com_status, subscription_id))

            # policy 163
            publicAccess = synapse.get('properties').get('publicNetworkAccess')
            if publicAccess == 'Enabled':
                non163.append(p163(name, location, non_status, subscription_id))
            else:
                com163.append(p163(name, location, com_status, subscription_id))

            diag = diagnostics(resourceId, head)
            if len(diag) > 0:
                com413.append(p413(name, location, com_status, subscription_id))
            else:
                non413.append(p413(name, location, non_status, subscription_id))

            # policy 478: Resource Locks
            locks = list_resource_locks(subscription_id, resourceGroupName, name, head)
            if not locks:
                non478.append(p478(name, location, non_status, subscription_id))
            else:
                com478.append(p478(name, location, com_status, subscription_id))

        # Send results for all policies
        p127_send(non127, com127)
        p143_send(non143, com143)
        p163_send(non163, com163)
        p344_send(non344, com344)
        p345_send(non345, com345)
        p346_send(non346, com346)
        p347_send(non347, com347)
        p348_send(non348, com348)
        p349_send(non349, com349)
        p413_send(non413, com413)
        p478_send(non478, com478)

        results_to_insert = (
            non127 + non143 + non163 + non344 + non345 + non346 + non347 + non348 + non349 + non413 + non478
        )
        if results_to_insert:
            logging.info(f"Inserting non-compliance results into DB for sub {subscription_id} (count={len(results_to_insert)})")
            insert_noncompliance_results_to_db(results_to_insert, subscription_id)
        else:
            logging.info(f"No non-compliance results to insert for sub {subscription_id}")

if __name__ == '__main__':
    main()
