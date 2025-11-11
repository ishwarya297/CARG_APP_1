import pytest
from unittest.mock import patch, MagicMock
import lambda_function

# Mock environment variables
import os
os.environ['SECRET_NAME'] = 'dummy-secret'
os.environ['REGION_NAME'] = 'dummy-region'
os.environ['ACCOUNT_MASTER_TABLE'] = 'account_master'
os.environ['ALERT_TABLE'] = 'alert_table'
os.environ['AZURE_SUBSCRIPTION_ID'] = 'subid'
os.environ['AZURE_TENANT_ID'] = 'tenantid'
os.environ['AZURE_CLIENT_ID'] = 'clientid'
os.environ['AZURE_CLIENT_SECRET'] = 'clientsecret'

# -------- Test get_secret --------

@patch('lambda_function.secretmanager_client')
def test_get_secret(mock_sm_client):
    mock_sm_client.get_secret_value.return_value = {'SecretString': '{"username": "user", "password": "pass"}'}
    result = lambda_function.get_secret()
    assert result == '{"username": "user", "password": "pass"}'

# -------- Test db_manager --------

@patch('lambda_function.get_secret')
@patch('lambda_function.psycopg2.connect')
def test_db_manager_success(mock_connect, mock_get_secret):
    mock_get_secret.return_value = '{"dbname":"db", "username":"user", "password":"pass", "proxy":"host", "port":"5432"}'
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = ("accesskey", "secretkey")
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mock_connect.return_value = mock_conn

    accesskey, secretkey = lambda_function.db_manager("test_account")
    assert accesskey == "accesskey"
    assert secretkey == "secretkey"

@patch('lambda_function.get_secret')
@patch('lambda_function.psycopg2.connect')
def test_db_manager_no_data(mock_connect, mock_get_secret):
    mock_get_secret.return_value = '{"dbname":"db", "username":"user", "password":"pass", "proxy":"host", "port":"5432"}'
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = None
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mock_connect.return_value = mock_conn

    accesskey, secretkey = lambda_function.db_manager("unknown_account")
    assert accesskey is None and secretkey is None

# -------- Test status_manager --------

@patch('lambda_function.get_secret')
@patch('lambda_function.psycopg2.connect')
def test_status_manager_success(mock_connect, mock_get_secret):
    mock_get_secret.return_value = '{"dbname":"db", "username":"user", "password":"pass", "proxy":"host", "port":"5432"}'
    mock_cursor = MagicMock()
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mock_connect.return_value = mock_conn

    # Should not raise exceptions
    lambda_function.status_manager("alertid")
    mock_cursor.execute.assert_called_once()

# -------- Test get_resource_group_name --------

@patch('lambda_function.StorageManagementClient')
@patch('lambda_function.ClientSecretCredential')
def test_get_resource_group_name(mock_cred, mock_storage_client):
    # Simulate storage account list
    mock_account = MagicMock()
    mock_account.name = 'myaccount'
    mock_account.id = '/subscriptions/123/resourceGroups/mygroup/providers/Microsoft.Storage/storageAccounts/myaccount'
    mock_storage_client.return_value.storage_accounts.list.return_value = [mock_account]

    rg = lambda_function.get_resource_group_name(
        'subid', 'tenantid', 'clientid', 'clientsecret', 'myaccount'
    )
    assert rg == 'mygroup'

@patch('lambda_function.StorageManagementClient')
@patch('lambda_function.ClientSecretCredential')
def test_get_resource_group_name_not_found(mock_cred, mock_storage_client):
    # Simulate no match
    mock_account = MagicMock()
    mock_account.name = 'otheraccount'
    mock_account.id = '/subscriptions/123/resourceGroups/othergroup/providers/Microsoft.Storage/storageAccounts/otheraccount'
    mock_storage_client.return_value.storage_accounts.list.return_value = [mock_account]

    with pytest.raises(Exception):
        lambda_function.get_resource_group_name(
            'subid', 'tenantid', 'clientid', 'clientsecret', 'notfound'
        )

# -------- Test main --------

@patch('lambda_function.get_resource_group_name')
@patch('lambda_function.status_manager')
@patch('lambda_function.get_secret')
@patch.dict(lambda_function.RULE_ACTIONS, {
    "SampleRule": (lambda *a, **k: True, "Success msg"),
})
def test_main_success(mock_get_secret, mock_status, mock_get_rg):
    event = {
        "ConfigRuleName": "SampleRule",
        "lambdaArgs": {
            "ACCOUNTID": "aid",
            "ALERTID": "alertid",
            "RESOURCETYPE": "storage",
            "ASSETID": "assetid",
            "REGIONNAME": "region"
        }
    }
    mock_get_rg.return_value = 'dummy-rg'
    mock_get_secret.return_value = '{"dbname":"db"}'

    resp = lambda_function.main(event, {})
    assert resp['statusCode'] == 200
    assert "Selfheal has been completed" in resp['title']

def test_success_response():
    msg = "Hello"
    resp = lambda_function.success_response(msg)
    assert resp['statusCode'] == 200
    assert 'Hello' in resp['body']

def test_failure_response():
    msg = "Fail"
    resp = lambda_function.failure_response(msg)
    assert resp['statusCode'] == 404
    assert 'Fail' in resp['body']
