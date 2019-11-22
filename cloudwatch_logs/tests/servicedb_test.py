import mock
import pytest
import botocore.session
import botocore
import boto3

from css.servicedb import create_table, store_service

# dynamodb_client = boto3.client("dynamodb")


@mock.patch("css.servicedb.boto3.resource")
def test_dynamodb_create_table_successful(mock_dynamo_resource):
    table = create_table(
        table_name="table", primary_key="primary", sort_key="sort"
    )
    print(table)


@mock.patch("css.servicedb.boto3.resource")
def test_dynamodb_create_table_client_error(mock_dynamo_resource, caplog):
    mock_dynamo_resource.return_value.create_table.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "ClientError"}}, "create_table"
    )
    with pytest.raises(
        botocore.exceptions.ClientError,
        match=r"An error occurred \(ClientError\) when calling the create_table operation:",
    ) as e:
        table = create_table(
            table_name="table", primary_key="primary", sort_key="sort"
        )
    mock_dynamo_resource.return_value.create_table.assert_called_once()
    assert len(caplog.records) == 1
    for record in caplog.records:
        assert record.levelname == "ERROR", "Wrong log message."
        assert record.message.startswith(
            "Cannot create table 'table':"
        ), "Wrong log message."
    caplog.clear()


@mock.patch("css.servicedb.boto3.resource")
def test_dynamodb_create_table_resource_in_use_error(mock_dynamo_resource):
    mock_dynamo_resource.return_value.create_table.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "ResourceInUseException"}}, "create_table"
    )
    table = create_table(
        table_name="table", primary_key="primary", sort_key="sort"
    )
    mock_dynamo_resource.return_value.create_table.assert_called_once()


@mock.patch("boto3.resource")
def test_dynamodb_store_service_successful(mock_dynamo_resource):
    mock_table = mock.MagicMock()
    mock_table.return_value = {
        "Attributes": {},
        "ConsumedCapacity": {},
        "ItemCollectionMetrics": {},
    }
    store_service(table=mock_table)
    mock_table.put_item.assert_called_once()


def test_dynamodb_store_data_client_error(caplog):
    mock_table = mock.MagicMock()
    mock_table.put_item.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "ClientError"}}, "put_item"
    )
    with pytest.raises(
        botocore.exceptions.ClientError,
        match=r"An error occurred \(ClientError\) when calling the put_item operation:",
    ) as e:
        store_service(
            table=mock_table,
            service_name="test",
            primary_key="primary_key",
            sort_key="sort_key",
        )
    mock_table.put_item.assert_called_once()
    assert len(caplog.records) == 1
    for record in caplog.records:
        assert record.levelname == "ERROR", "Wrong log message."
        assert record.message.startswith(
            "DynamoDB error with primary_key 'primary_key' and sort_key 'sort_key':"
        ), "Wrong log message."
    caplog.clear()


def test_dynamodb_store_data_no_name_client_error(caplog):
    mock_table = mock.MagicMock()
    mock_table.put_item.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "ClientError"}}, "put_item"
    )
    with pytest.raises(botocore.exceptions.ClientError) as e:
        store_service(table=mock_table)
    mock_table.put_item.assert_called_once()
    assert str(e.value).startswith(
        "An error occurred (ClientError) when calling the put_item operation:"
    ), "Wrong exception message."
    assert len(caplog.records) == 1
    for record in caplog.records:
        assert record.levelname == "ERROR", "Wrong log message."
        assert record.message.startswith(
            "DynamoDB error with primary_key 'None' and sort_key 'None':"
        ), "Wrong log message."
    caplog.clear()


# def test_dynamodb_store_data_no_keys_client_error(caplog):
#     mock_table = mock.MagicMock()
#     mock_table.put_item.side_effect = botocore.exceptions.ClientError({"Error": {"Code": "ClientError"}}, "put_item")
#     with pytest.raises(botocore.exceptions.ClientError) as error_context:
#         print(f"=============1")
#         store_service(table=mock_table)
#         print(f"=============2")
#         mock_table.put_item.assert_called_once()
#         print(f"============={context.exception}")
#     print(f"CAPLOG==={caplog.text}")
#     print(f"CAPLOG==={caplog}")
#     assert "DynamoDB error with primary_key 'None' and sort_key 'None'" in str(error_context.value), "Wrong exception message."
#     90/0
#
# def test_dynamodb_store_data_no_table_error(caplog):
#     with pytest.raises(ValueError) as error_context:
#         store_service()
#
#
#     print(f"CAPLOG==={caplog.text}")
#     print(f"CAPLOG==={caplog}")
#     assert "" in str(error_context.value), "Wrong exception message."
#     assert "No table supplied." in caplog.text, "Critical log message missing."
#     90/0
#
#     # # create_table_mock = mock.patch("botocore.client.BaseClient._make_api_call", side_effect=dynamodb_client.exceptions.ClientError)
#     # # with pytest.raises(dynamodb_client.exceptions.ParamValidationError) as context:
#     # #     table = create_table()
#     # # create_table_mock = mock.patch("dynamodb.create_table", side_effect=dynamodb_client.exceptions.ClientError)
#     # # create_table_mock = mock.MagicMock()
#     # # create_table_mock.side_effect = dynamodb_client.exceptions.ClientError
#     # mock_table = mock.Mock()
#     # # mock_table.put_item.return_value = []
#     # mock_table.put_item.side_effect = dynamodb_client.exceptions.ClientError
#     # mock_dynamo_resource.Table.return_value = mock_table
#     # table = store_service(table=mock_table)
#
#     # # mock_create_table = mock.Mock()
#     # # mock_dynamo_resource.create_table = mock_create_table
#     # # mock_dynamo_resource.create_table.side_effect = Exception("asd")
#     # # table = create_table(table_name="table",primary_key="primary", sort_key="sort")
#     # # mock_dynamo_resource.create_table.assert_called_once()
#     # print("124")
#     # with mock.patch("botocore.client.BaseClient._make_api_call") as mocked:
#     #     mocked.side_effect = dynamodb_client.exceptions.ClientError
#     #     with pytest.raises(dynamodb_client.exceptions.ClientError) as context:
#     #         table = create_table(table_name="table",primary_key="primary", sort_key="sort")
#     #     print(context)
#
