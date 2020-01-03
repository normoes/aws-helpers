import logging
import mock
import pytest
from datetime import datetime
import botocore.session
import botocore
import boto3

from css.aws_get_logs import get_logs, get_logs_filter_streams


def test_get_logs_successful():
    """Successfully filtering log events.

    Source: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/logs.html?highlight=get_log_events#CloudWatchLogs.Client.get_log_events
    """

    mock_client = mock.MagicMock()
    mock_client.get_log_events.return_value = {
        'events': [
            {
                'timestamp': 123,
                'message': 'string',
                'ingestionTime': 123
            },
        ],
        'nextForwardToken': 'string',
        'nextBackwardToken': 'string'
    }
    get_logs(
        client=mock_client,
    )
    mock_client.get_log_events.assert_called_once()


def test_get_logs_no_credentials_error(caplog):
    mock_client = mock.MagicMock()
    mock_client.get_log_events.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "NoCredentialsError"}}, "get_log_events"
    )

    caplog.set_level(logging.ERROR, logger="AWSGetLogs")
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        get_logs(
            client=mock_client,
        )
    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == 1
    mock_client.get_log_events.assert_called_once()
    
    print(caplog.records)
    assert len(caplog.records) == 1
    for record in caplog.records:
        assert record.levelname == "ERROR", "Wrong log message."
        assert record.message.startswith(
            "Could not find AWS credentials. Error: "
        ), "Wrong log message."
    caplog.clear()


def test_get_logs_client_error(caplog):
    mock_client = mock.MagicMock()
    mock_client.get_log_events.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "ClientError"}}, "get_log_events"
    )

    caplog.set_level(logging.ERROR, logger="AWSGetLogs")
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        get_logs(
            client=mock_client,
        )
    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == 1
    mock_client.get_log_events.assert_called_once()

    assert len(caplog.records) == 1
    for record in caplog.records:
        assert record.levelname == "ERROR", "Wrong log message."
        assert record.message.startswith(
            "Error: "
        ), "Wrong log message."
    caplog.clear()


def test_get_logs_filter_streams_successful(caplog):
    """Successfully filtering log events in a given stream.

    Source: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/logs.html?highlight=ilter_log_events#CloudWatchLogs.Client.filter_log_events
    """

    mock_client = mock.MagicMock()
    mock_client.filter_log_events.return_value = {
        'events': [
            {
                'logStreamName': 'string',
                'timestamp': 123,
                'message': 'string',
                'ingestionTime': 123,
                'eventId': 'string'
            },
        ],
        'searchedLogStreams': [
            {
                'logStreamName': 'string',
                'searchedCompletely': True
            },
        ]
    }

    get_logs_filter_streams(log_group="log_group", log_stream="log_stream", limit=1, client=mock_client,).__next__()

    mock_client.filter_log_events.assert_called_once()

    assert len(caplog.records) == 2
    for record in caplog.records:
        assert record.levelname == "INFO", "Wrong log message."
    assert caplog.records[0].message.startswith(
        "Going '3 hours' back in time."
    ), "Wrong log message."
    assert caplog.records[1].message.startswith(
        "Limiting results to '1'."
    ), "Wrong log message."
    caplog.clear()


def test_get_logs_filter_streams_successful_two_runs(caplog):
    """Successfully filtering log events in a given stream.

    Making two requests.

    Source: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/logs.html?highlight=ilter_log_events#CloudWatchLogs.Client.filter_log_events
    """

    mock_client = mock.MagicMock()
    mock_client.filter_log_events.side_effect = [{
        'events': [
            {
                'logStreamName': 'string',
                'timestamp': 123,
                'message': 'string',
                'ingestionTime': 123,
                'eventId': 'string'
            },
        ],
        'searchedLogStreams': [
            {
                'logStreamName': 'string',
                'searchedCompletely': True
            },
        ],
        "nextToken": "next_token"
    },
    {
        'events': [
            {
                'logStreamName': 'string_',
                'timestamp': 1234,
                'message': 'string_',
                'ingestionTime': 1234,
                'eventId': 'string_'
            },
        ],
        'searchedLogStreams': [
            {
                'logStreamName': 'string_',
                'searchedCompletely': False
            },
        ]
    }]

    gen_func = get_logs_filter_streams(log_group="log_group", log_stream="log_stream", limit=1, client=mock_client,)
    gen_func.__next__()
    mock_client.filter_log_events.assert_called_once()
    gen_func.__next__()
    assert 2 == mock_client.filter_log_events.call_count

    assert len(caplog.records) == 2
    for record in caplog.records:
        assert record.levelname == "INFO", "Wrong log message."
    assert caplog.records[0].message.startswith(
        "Going '3 hours' back in time."
    ), "Wrong log message."
    assert caplog.records[1].message.startswith(
        "Limiting results to '1'."
    ), "Wrong log message."
    caplog.clear()



def test_get_logs_filter_streams_no_credentials_error(caplog):
    """No credentials when filtering log events in a given stream.
    """

    mock_client = mock.MagicMock()
    mock_client.filter_log_events.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "NoCredentialsError"}}, "filter_log_events"
    )

    caplog.set_level(logging.ERROR, logger="AWSGetLogs")
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        get_logs_filter_streams(client=mock_client,).__next__()
        # for test in get_logs_filter_streams(client=mock_client,):
        #     print(test)
    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == 1

    mock_client.filter_log_events.assert_called_once()

    assert len(caplog.records) == 1
    for record in caplog.records:
        assert record.levelname == "ERROR", "Wrong log message."
        assert record.message.startswith(
            "Could not find AWS credentials. Error: "
        ), "Wrong log message."
    caplog.clear()


def test_get_logs_filter_streams_client_error(caplog):
    """Boto3 client error when filtering log events in a given stream.
    """

    mock_client = mock.MagicMock()
    mock_client.filter_log_events.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "ClientError"}}, "filter_log_events"
    )

    caplog.set_level(logging.ERROR, logger="AWSGetLogs")
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        get_logs_filter_streams(client=mock_client,).__next__()
        # for test in get_logs_filter_streams(client=mock_client,):
        #     print(test)
    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == 1

    mock_client.filter_log_events.assert_called_once()

    assert len(caplog.records) == 1
    for record in caplog.records:
        assert record.levelname == "ERROR", "Wrong log message."
        assert record.message.startswith(
            "Error: "
        ), "Wrong log message."
    caplog.clear()
