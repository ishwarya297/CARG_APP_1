import json
from azure.identity import ClientSecretCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.policyinsights import PolicyInsightsClient
from azure.mgmt.policyinsights.models import PolicyStatesResource, QueryOptions
import psycopg2
import boto3
import datetime
import requests
import base64
import os
import time
import logging
from uuid import uuid4
from botocore.exceptions import ClientError
from dotenv import load_dotenv
from datetime import datetime as dt, timedelta

# Python 3.11+ has datetime.UTC; provide fallback for older versions
try:
    from datetime import UTC
except ImportError:
    from datetime import timezone as _tz
    UTC = _tz.utc

# Load environment variables from .env file
load_dotenv()

# ──────────────────────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# ──────────────────────────────────────────────────────────────────────────────
# Env constants used across the module
# ──────────────────────────────────────────────────────────────────────────────
AWS_REGION = os.getenv("AWS_REGION") or os.getenv("REGION_NAME")
DYNAMO_TABLE = os.getenv("ASSET_DYNAMO_TABLE", "Azure_AssetDiscoveryLogs")
DDB_TTL_DAYS = int(os.environ.get("DDB_TTL_DAYS", "90"))  # <<— your TTL days knob

# ──────────────────────────────────────────────────────────────────────────────
# Helpers: base64 + timestamp
# ──────────────────────────────────────────────────────────────────────────────
def base64decoder(encoded_string):
    try:
        decoded_bytes = base64.b64decode(encoded_string)
        decoded_string = decoded_bytes.decode('utf-8')
        return decoded_string
    except Exception as e:
        print(f"Error decoding base64 string: {e}")
        return None

def iso_utc_now():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

# ──────────────────────────────────────────────────────────────────────────────
# Dynamo bootstrap: create table if absent + enable TTL (your pattern)
# ──────────────────────────────────────────────────────────────────────────────
def create_dynamo_table_if_not_exists(dynamo_table_name: str = None, region: str = None):
    """
    Ensures a DynamoDB table with PK: log_id (S) exists and has TTL enabled on 'ttl'.
    Uses your try/except ValidationException pattern for idempotent TTL enablement.
    """
    try:
        dynamo_table_name = dynamo_table_name or DYNAMO_TABLE
        AWS_REGION_LOCAL = region or AWS_REGION
        if not AWS_REGION_LOCAL:
            raise RuntimeError("AWS region is not set. Define AWS_REGION or REGION_NAME in env.")

        client = boto3.client("dynamodb", region_name=AWS_REGION_LOCAL)
        if dynamo_table_name in client.list_tables()["TableNames"]:
            logging.info(f"DynamoDB table '{dynamo_table_name}' already exists.")
            # Ensure TTL is enabled (idempotent) — your logic
            try:
                client.update_time_to_live(
                    TableName=dynamo_table_name,
                    TimeToLiveSpecification={"Enabled": True, "AttributeName": "ttl"}
                )
            except client.exceptions.ValidationException:
                pass
            return

        client.create_table(
            TableName=dynamo_table_name,
            KeySchema=[{"AttributeName": "log_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "log_id", "AttributeType": "S"}],
            BillingMode='PAY_PER_REQUEST'
        )
        waiter = client.get_waiter('table_exists')
        waiter.wait(TableName=dynamo_table_name)

        # Enable TTL on 'ttl' (idempotent) — your logic
        client.update_time_to_live(
            TableName=dynamo_table_name,
            TimeToLiveSpecification={"Enabled": True, "AttributeName": "ttl"}
        )
        logging.info(f"Created DynamoDB table '{dynamo_table_name}' and enabled TTL.")
    except Exception as e:
        logging.error(f"Failed to create/prepare DynamoDB table: {e}")

# ──────────────────────────────────────────────────────────────────────────────
# DynamoDB logger (for Azure_AssetDiscoveryLogs)
# Writes per-item TTL using your logic
# ──────────────────────────────────────────────────────────────────────────────
class DynamoLogger:
    def __init__(self, table_name=None, region=None):
        self.table_name = table_name or DYNAMO_TABLE
        self.region = region or AWS_REGION
        self._table = boto3.resource("dynamodb", region_name=self.region).Table(self.table_name)

    def _make_log_id(self, account_id: str, resource_id: str) -> str:
        ms = int(time.time() * 1000)
        return f"{account_id}#{ms}#{uuid4().hex[:8]}"

    def _compute_ttl_epoch(self) -> int:
        # Your TTL logic: days -> epoch seconds
        ttl_dt = dt.now(UTC) + timedelta(days=DDB_TTL_DAYS)
        return int(ttl_dt.timestamp())

    def log_asset(self, *, account_id, resource_id, resource_type, asset_type, region, level="INSERT", message=""):
        item = {
            "log_id": self._make_log_id(account_id, resource_id),
            "account_id": str(account_id),
            "resource_id": str(resource_id),
            "resource_type": str(resource_type),
            "asset_type": str(asset_type),
            "region": str(region or "global"),
            "level": str(level),
            "message": message or "",
            "timestamp": iso_utc_now(),
            "ttl": self._compute_ttl_epoch(),  # <<— per-item TTL written as Number (seconds)
        }
        try:
            self._table.put_item(Item=item)
        except Exception as e:
            # non-fatal: do not break discovery if logging fails
            print(f"DynamoDB put_item failed: {e}")

# ──────────────────────────────────────────────────────────────────────────────
# RDS helpers
# ──────────────────────────────────────────────────────────────────────────────
def data_flash(connection):
    try:
        cursor = connection.cursor()
        delete_query = "DELETE FROM ccsadminnew.ccsazureassets;"
        cursor.execute(delete_query)
        connection.commit()
    except Exception as e:
        print(e)

def alert_table_data_flash(connection):
    try:
        cursor = connection.cursor()
        truncate_query = "TRUNCATE TABLE ccsadminnew.ccsazurealerts RESTART IDENTITY;"
        cursor.execute(truncate_query)
        connection.commit()
    except Exception as e:
        print(e)

def insert_db(batch):
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        insert_query = """INSERT INTO ccsadminnew.ccsazureassets
            (assetname, resourcetype, assettype, accountid, cloudtype, region, createdby, createdon, modifiedby, modifiedon)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s);"""
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

# ──────────────────────────────────────────────────────────────────────────────
# Azure discovery
# ──────────────────────────────────────────────────────────────────────────────
class AzureClient:
    cloudType = 'Azure'
    createtime = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def __init__(self, client_id, client_secret, tenant_id, subscription_id, dynamo_logger: DynamoLogger = None):
        self.subscription_id = subscription_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.tenant_id = tenant_id
        self.credential = ClientSecretCredential(self.tenant_id, self.client_id, self.client_secret)
        self.resource_client = ResourceManagementClient(self.credential, self.subscription_id)
        self.policy_client = PolicyInsightsClient(self.credential, self.subscription_id)
        self.dynamo = dynamo_logger  # may be None

    def get_asset(self):
        try:
            resource_group_list = self.resource_client.resource_groups.list()
            group_list = list(resource_group_list)
            if resource_group_list is None:
                print("No resource groups found in the subscription.")
                return {'statusCode': 404, 'body': json.dumps('No data found')}

            try:
                for group in group_list:
                    # List resources in the resource group
                    resources = self.resource_client.resources.list_by_resource_group(group.name)
                    batch = []
                    for resource in resources:
                        # Derive resource_type and asset_type from ARM type (e.g., "Microsoft.Storage/storageAccounts")
                        try:
                            resource_type, asset_type = resource.type.split("/", 1)
                        except ValueError:
                            resource_type, asset_type = resource.type, ""

                        # Normalize to match your original output style
                        asset_type = asset_type.capitalize()
                        resource_type_lower = resource_type.lower()

                        managed_by = resource.managed_by or 'None'

                        # Prepare RDS row
                        batch.append((
                            resource.name,
                            resource_type_lower,
                            asset_type,
                            self.subscription_id,
                            self.cloudType,
                            resource.location,
                            managed_by,
                            self.createtime,
                            managed_by,
                            self.createtime
                        ))

                        # Log to DynamoDB (optional)
                        if self.dynamo:
                            self.dynamo.log_asset(
                                account_id=self.subscription_id,
                                resource_id=resource.id,
                                resource_type=resource_type_lower,
                                asset_type=asset_type,
                                region=resource.location,
                                level="INSERT",
                                message=f"Asset discovered in RG '{group.name}': {resource.name}"
                            )

                    # Insert batch to RDS after each RG
                    if batch:
                        insert_db(batch)

                return group_list

            except Exception as e:
                print(f"Error: {e}")
        except Exception as e:
            print(f"Error : {e}")

# ──────────────────────────────────────────────────────────────────────────────
# Non-compliance (unchanged, no Dynamo writes)
# ──────────────────────────────────────────────────────────────────────────────
def non_compliant_data_insertion(resource_id, policy_definition_id, group_name, credential):
    data = []
    try:
        policy_definition_id = f"/providers/Microsoft.Authorization/policyDefinitions/{policy_definition_id}"
        url = f"https://management.azure.com{policy_definition_id}?api-version=2020-09-01"
        headers = {
            "Authorization": f"Bearer {credential.get_token('https://management.azure.com/.default').token}"
        }
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            policy_definition = response.json()
            policy_description = policy_definition['properties']['description']
            data.append({
                'group_name': group_name,
                'resource_id': resource_id,
                'policy_definition_id': policy_definition_id,
                'policy_description': policy_description
            })
            # (Persist to alerts via SP here if you wish)
        else:
            print(f"Failed to retrieve the policy definition. Status code: {response.status_code}, Response: {response.text}")

    except Exception as e:
        print(f"Error in nc data insert: {e}")

def non_compliant_data_collection(group_list, resourceManager, policyClient, credential):
    credential = credential
    if len(group_list) == 0:
        print("No resource groups found in the subscription.")
    try:
        for group in group_list:
            resource = resourceManager
            policy_client = policyClient
            resources = resource.resources.list_by_resource_group(group.name)
            for resource in resources:
                policy_states = policy_client.policy_states.list_query_results_for_resource(
                    policy_states_resource=PolicyStatesResource.LATEST,
                    resource_id=resource.id
                )
                for state in policy_states:
                    compliance_state = "Compliant" if state.is_compliant else "Non-Compliant"
                    if not state.is_compliant:
                        definition_id = state.policy_definition_name
                        resource_id = state.resource_id
                        group_name = group.name
                        non_compliant_data_insertion(resource_id, definition_id, group_name, credential)

    except Exception as e:
        print(f"Error: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps('Error in non-compliant data collection')
        }

# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────
def main():
    try:
        start_time = datetime.datetime.now()
        connection = get_db_connection()
        alert_table_data_flash(connection)
        print("starttime", start_time)
        data_flash(connection)

        # Ensure Dynamo table exists & TTL is set before logging starts (your pattern)
        create_dynamo_table_if_not_exists(DYNAMO_TABLE, AWS_REGION)

        # Create Dynamo logger (per-item TTL uses your logic)
        dynamo_logger = DynamoLogger(table_name=DYNAMO_TABLE, region=AWS_REGION)

        cursor = connection.cursor()
        cursor.execute("SELECT clientid, clientsecret, tenantid, subscriptionid FROM ccsadminnew.ccscloudaccountmaster where cloudtype_id=2;")
        rows = cursor.fetchall()
        if not rows:
            return {
                'statusCode': 404,
                'body': json.dumps('No data found')
            }
        try:
            for row in rows:
                client_id_decoded = base64decoder(row[0])
                client_secret_decoded = base64decoder(row[1])
                tenant_id_decoded = base64decoder(row[2])
                client = AzureClient(client_id_decoded, client_secret_decoded, tenant_id_decoded, row[3], dynamo_logger)
                resourceManager = client.resource_client
                policyClient = client.policy_client
                credential = client.credential
                group_list = client.get_asset()
                # Keep non-compliance path unchanged (no Dynamo)
                non_compliant_data_collection(group_list, resourceManager, policyClient, credential)
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
                'body': json.dumps('Azure Inventory data successfullly inserted')
                }

    except Exception as e:
        print(f"Error: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps('Error create connection or inserting Azure Inventory data')
        }

if __name__ == "__main__":
    main()
