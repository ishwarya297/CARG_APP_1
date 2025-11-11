import json
from azure.identity import ClientSecretCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.policyinsights import PolicyInsightsClient
from azure.mgmt.policyinsights.models import PolicyStatesResource, QueryOptions
import psycopg2
import boto3
import datetime
import requests
from botocore.exceptions import ClientError
from dotenv import load_dotenv
import os
# Load environment variables from .env file
load_dotenv()

def data_flush(connection):
    try:
        connection = connection
        cursor = connection.cursor()
        delete_query = "DELETE FROM ccsadminnew.ccsazureassets;"
        response = cursor.execute(delete_query)
        commit = connection.commit()
    except Exception as e:
        print(e)

class AzureClient:
    cloudType = 'Azure'
    bussinessName = 'None'
    applicationName = 'None'
    createtime = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    def __init__(self,client_id, client_secret, tenant_id,subscription_id):
        self.subscription_id = subscription_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.tenant_id = tenant_id
        self.credential = ClientSecretCredential(self.tenant_id, self.client_id, self.client_secret)
        self.resource_client = ResourceManagementClient(self.credential, self.subscription_id)
        self.policy_client = PolicyInsightsClient(self.credential, self.subscription_id)
    def get_asset(self):
        try:
            resource_group_list = self.resource_client.resource_groups.list()
            group_list = list(resource_group_list)
            if resource_group_list is None:
                print("No resource groups found in the subscription.")
                return {
                    'statusCode': 404,
                    'body': 'No data found'
                }
            try:
                for group in group_list:
                # List resources in the resource group
                    resources = self.resource_client.resources.list_by_resource_group(group.name)

                    batch = []
                    for resource in resources:

                        if resource.managed_by is None:
                            resource.managed_by = 'None'
                            resource_type, asset_type = resource.type.split("/", 1)
                            batch.append((resource.name, resource_type, asset_type, self.subscription_id, self.cloudType, resource.location, self.bussinessName, self.applicationName,resource.managed_by, self.createtime, resource.managed_by, self.createtime))
                        else:
                            batch.append((resource.name, resource_type, asset_type, self.subscription_id, self.cloudType, resource.location, self.bussinessName, self.applicationName,resource.managed_by, self.createtime, resource.managed_by, self.createtime))
                    try:
                        insert_db(batch)
                    except Exception as e:
                        print(f"Error : {e}")
                return(group_list)
            except Exception as e:
                print(f"Error: {e}")
        except Exception as e:
            print(f"Error : {e}")

def insert_db(batch):
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        insert_query = """INSERT INTO ccsadminnew.ccsazureassets(assetname, resourcetype, assettype, accountid, cloudtype, region, businessname, applicationname, createdby, createdon, modifiedby, modifiedon)VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);"""
        cursor.executemany(insert_query, batch)
        connection.commit()
    except Exception as e:
        print(f"Error : {e}")

def get_secret():
    secret_name = os.environ.get('SECRET_NAME')
    region_name = os.environ.get('REGION_NAME')
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

def main():
    try:
        start_time = datetime.datetime.now()
        print("starttime", start_time)
        connection = get_db_connection()
        data_flush(connection)
        cursor = connection.cursor()
        cursor.execute("SELECT clientid, clientsecret, tenantid, subscriptionid FROM ccsadminnew.ccscloudaccountmaster where cloudtype_id=2;")
        rows = cursor.fetchall()
        if not rows:
            return {
                'statusCode': 404,
                'body': 'No data found'
            }
        try:
            for row in rows:
                client = AzureClient(row[0], row[1], row[2], row[3])
                resourceManager = client.resource_client
                policyClient = client.policy_client
                credential = client.credential
                client.get_asset()
            cursor.close()
            connection.close()
            end_time = datetime.datetime.now()
            print("endtime", end_time)
            elapsed_time = end_time - start_time
            print("Elapsed time:", elapsed_time)
        except Exception as e:
            print(f"Error in calling functions: {e}")
        return {
            'statusCode': 200,
            'body': 'Azure Inventory data successfullly inserted'
        }

    except Exception as e:
        print(f"Error: {e}")
        return {
            'statusCode': 500,
            'body': 'Error create connection or inserting Azure Inventory data'
        }

if __name__ == "__main__":
    main()
