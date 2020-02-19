#!/usr/bin/env python

"""
Goal:
  * Get Cloudwatch logs.

How to:
  * Get help
    - aws_get_logs.py -h
  * Get recent streams
    - Get the most recent events
    - aws_get_logs recent-streams -h
    - python aws_get_logs.py recent-streams --region <aws_region> --group <log_group>
  * Filter a log stream:
    - Get the most recent log events from the given log stream.
    - aws_get_logs get-stream -h
    - python aws_get_logs.py get-stream --region <aws_region> --group <log_group> --stream <log_stream_prefix>  --start-time 24 --time-unit "hours" --limit 30
  * Follow a log stream:
    - Get the most recent log events from the given log stream and keep on listening.
    - aws_get_logs follow-stream -h
    - python aws_get_logs.py follow-stream --region <aws_region> --group <log_group> --stream <log_stream_prefix>  --start-time 24 --time-unit "hours" --limit 30
  * Query log events:
    - It's possiblet o query log events using AWS CloudWatch Insights.
    - aws_get_logs insights -h
    - python aws_get_logs.py insights --region <aws_region> --group <log_group> --start_time 1 --limit 1000 --query 'fields @timestamp, @message | sort @timestamp desc | limit 20'
"""

import os
import argparse
import boto3
import botocore
import logging
import sys
import functools
import json
from time import sleep
from datetime import datetime, timedelta

logging.basicConfig()
logger = logging.getLogger("AWSGetLogs")
logger.setLevel(logging.INFO)

REGION_DEFAULT = "eu-west-1"
START_TIME_DEFAULT = 3
TIME_UNIT_DEFAULT = "hours"
LIMIT_DEFAULT = 20
QUERY_DEFAULT = "fields @timestamp, @message | sort @timestamp desc | limit 20"

REGION = os.environ.get("AWS_REGION", REGION_DEFAULT)
LOG_GROUP = os.environ.get("LOG_GROUP", None)
LOG_STREAM = os.environ.get("LOG_STREAM", None)
START_TIME = os.environ.get("START_TIME", START_TIME_DEFAULT)
TIME_UNIT = os.environ.get("TIME_UNIT", TIME_UNIT_DEFAULT)
LIMIT = os.environ.get("LIMIT", LIMIT_DEFAULT)
QUERY = os.environ.get("QUERY", QUERY_DEFAULT)


def init_log_message(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time_offset = kwargs.get("start_time_offset", START_TIME_DEFAULT)
        time_unit = kwargs.get("time_unit", TIME_UNIT_DEFAULT)
        limit = kwargs.get("limit", LIMIT_DEFAULT)
        logger.info(f"Going '{start_time_offset} {time_unit}' back in time.")
        logger.info(f"Limiting results to '{limit}'.")
        return func(*args, **kwargs)

    return wrapper


def make_time(
    start_time_offset: int = START_TIME_DEFAULT, time_unit=TIME_UNIT_DEFAULT
):
    """Create query start and end times.

    The end_time is now.
    The start_time is derived from end_time andagiven number of hours to go back in time.

    For now any given value is considered to represent hours.
    """

    end_time = datetime.utcnow()
    start_time_dict = {time_unit: start_time_offset}
    start_time = end_time - timedelta(**start_time_dict)
    end_time = int(datetime.timestamp(end_time)) * 1000
    start_time = int(datetime.timestamp(start_time) * 1000)
    return start_time, end_time


@init_log_message
def show_most_recent_log_streams(
    log_group=LOG_GROUP, limit_results=5, client=None, debug=False
):
    # Add 'nosec' comment to make bandit ignore [B105:hardcoded_password_string]
    next_token = "first"  # nosec
    parameters = {
        "logGroupName": log_group,
        "orderBy": "LastEventTime",
        "descending": True,
    }
    most_recent_log_streams = {}
    limit = limit_results
    while next_token:
        try:
            response = client.describe_log_streams(**parameters)
            if response:
                next_token = response.get("nextToken", "")
                parameter_next_token = {"nextToken": next_token}
                if next_token:
                    parameters.update(parameter_next_token)
                else:
                    parameters.pop("nextToken", None)
                log_streams = response.get("logStreams", [])
                # logger.info(log_streams)
                for log_stream in log_streams:
                    log_stream_name = log_stream.get("logStreamName", None)
                    if (
                        log_stream_name
                        and log_stream_name not in most_recent_log_streams
                    ):
                        stream_main_name = "/".join(
                            log_stream_name.split("/")[:-1]
                        )
                        last_event_timestamp = log_stream.get(
                            "lastEventTimestamp", None
                        )
                        logger.info(stream_main_name)
                        if (
                            last_event_timestamp
                            and stream_main_name
                            not in most_recent_log_streams.keys()
                        ):
                            logger.info(log_stream)
                            most_recent_log_streams[stream_main_name] = {
                                "lastEventTimestamp": last_event_timestamp
                            }
                            limit -= 1
                            if limit == 0:
                                # Do not request more log streams.
                                next_token = None
                                # Stop adding more log streams.
                                break

                logger.debug(json.dumps(response, indent=2))
            else:
                print(f"No response received")
        except (botocore.errorfactory.ClientError) as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "NoCredentialsError":
                logger.error(
                    f"Could not find AWS credentials. Error: {str(e)}."
                )
            elif error_code == "InvalidParameterException":
                logger.error(
                    f"Wrong parameters with log group '{log_group}'. Error: {str(e)}."
                )
            elif error_code == "ResourceNotFoundException":
                logger.error(
                    f"Did not find log group '{log_group}' with log stream '{log_stream}'. Error: {str(e)}."
                )
            else:
                logger.error(f"Error: {str(e)}.")
            sys.exit(1)
    if most_recent_log_streams:
        print(most_recent_log_streams)
    else:
        print(f"No streams found with log group '{log_group}'")


@init_log_message
def get_logs_filter_streams(
    log_group=LOG_GROUP,
    log_stream=LOG_STREAM,
    limit=LIMIT,
    start_time_offset=START_TIME,
    time_unit=TIME_UNIT,
    follow=False,
    client=None,
    debug=False,
):
    # Add 'nosec' comment to make bandit ignore [B105:hardcoded_password_string]
    next_token = "first"  # nosec
    start_time, end_time = make_time(start_time_offset, time_unit=time_unit)
    parameters = {
        "logGroupName": log_group,
        "logStreamNamePrefix": log_stream,
        "limit": limit,
        "startTime": start_time,
        "endTime": end_time,
    }
    if follow:
        start_time = end_time
        create_new_start_time = False
    while True if follow else next_token:
        try:
            if not next_token and follow:
                create_new_start_time = True
                end_time = int(datetime.timestamp(datetime.utcnow())) * 1000
                parameters.update({"endTime": end_time})
                parameters.update({"startTime": start_time - 1})

            response = client.filter_log_events(**parameters)

            if response:
                next_token = response.get("nextToken", "")
                if next_token:
                    parameters.update({"nextToken": next_token})
                else:
                    parameters.pop("nextToken", None)
                log_events = response.get("events", [])
                if follow:
                    if log_events:
                        if create_new_start_time:
                            create_new_start_time = not create_new_start_time
                            start_time = end_time
                for log_event in log_events:
                    # log_stream_name = log_event.get("logStreamName", None)
                    # timestamp = log_event.get("timestamp", -1)
                    message = log_event.get("message", "")
                    yield message
        except (botocore.errorfactory.ClientError) as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "NoCredentialsError":
                logger.error(
                    f"Could not find AWS credentials. Error: {str(e)}."
                )
            elif error_code == "InvalidParameterException":
                logger.error(
                    f"Wrong parameters with log group '{log_group}' and log stream '{log_stream}'. Error: {str(e)}."
                )
            elif error_code == "ResourceNotFoundException":
                logger.error(
                    f"Did not find log group '{log_group}' with log stream '{log_stream}'. Error: {str(e)}."
                )
            else:
                logger.error(f"Error: {str(e)}.")
            sys.exit(1)


# @init_log_message
# def get_logs_filter_streams_follow(log_group=LOG_GROUP, log_stream=LOG_STREAM, limit=LIMIT, start_time_offset=START_TIME, time_unit=TIME_UNIT, client=None, debug=False):
#     next_token = "first"
#     start_time, end_time = make_time(start_time_offset, time_unit=time_unit)
#     parameters = {"logGroupName": log_group, "logStreamNamePrefix": log_stream, "limit": limit, "startTime": start_time, "endTime": end_time}
#     while True:
#         try:
#             response = client.filter_log_events(**parameters)
#             if response:
#                 next_token = response.get("nextToken", "")
#                 if next_token:
#                     parameters.update({"nextToken": next_token})
#                 else:
#                     parameters.pop("nextToken", None)
#                 log_events = response.get("events", [])
#                 for log_event in log_events:
#                     log_stream_name = log_event.get("logStreamName", None)
#                     timestamp = log_event.get("timestamp", -1)
#                     message = log_event.get("message", "")
#                     yield message
#         except (botocore.errorfactory.ClientError) as e:
#             error_code = e.response["Error"]["Code"]
#             if error_code == "InvalidParameterException":
#                 logger.error(f"Wrong parameters with log group '{log_group}'. Error: {str(e)}.")
#                 sys.exit(1)
#             elif error_code == "ResourceNotFoundException":
#                 logger.error(f"Did not find log group '{log_group}'. Error: {str(e)}.")
#                 sys.exit(1)


@init_log_message
def get_logs_using_insights(
    log_group=LOG_GROUP,
    query=QUERY,
    limit=LIMIT,
    start_time_offset=START_TIME,
    time_unit=TIME_UNIT,
    client=None,
):
    start_time, end_time = make_time(start_time_offset, time_unit=time_unit)
    parameters = {
        "logGroupName": log_group,
        "startTime": start_time,
        "endTime": end_time,
        "queryString": query,
        "limit": limit,
    }
    most_recent_log_streams = []
    logger.info(f"Starting query '{parameters['queryString']}'")
    query_id = ""
    result = []
    try:
        response = client.start_query(**parameters)
        if response:
            log_streams = response.get("logStreams", [])
            for log_stream in log_streams:
                log_stream_name = log_stream.get("logStreamName", None)
                if (
                    log_stream_name
                    and log_stream_name not in most_recent_log_streams
                ):
                    most_recent_log_streams.append(log_stream_name)
            # print(json.dumps(response, indent=4))

            query_id = response.get("queryId", "")
        else:
            print(f"No response received")
    except (botocore.errorfactory.ClientError) as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "NoCredentialsError":
            logger.error(f"Could not find AWS credentials. Error: {str(e)}.")
        elif error_code == "MalformedQueryException":
            logger.error(
                f"Error in query '{parameters['queryString']}'. Error: {str(e)}"
            )
        elif error_code == "InvalidParameterException":
            logger.error(
                f"Wrong parameters with log group '{log_group}' and log stream '{log_stream}'. Error: {str(e)}"
            )
        elif error_code == "ResourceNotFoundException":
            logger.error(
                f"Did not find log group '{log_group}' with log stream '{log_stream}'. Error: {str(e)}"
            )
        else:
            logger.error(f"Error: 'str(e)'")
        sys.exit(1)

    status = ""
    try:
        logger.debug(f"Checking query '{query_id}'")
        retries = 180
        while retries >= 0:
            # while not status == "Complete":
            retries -= 1
            sleep(1)
            response = client.get_query_results(queryId=query_id)
            # Possible query status values
            # 'Scheduled'|'Running'|'Complete'|'Failed'|'Cancelled'
            # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/logs.html#CloudWatchLogs.Client.get_query_results
            status = response.get("status", "")
            logger.debug(f"Query '{query_id}' status is '{status}'.")
            if status == "Complete":
                break

        if not status == "Complete":
            logger.warning(f"Query not ready")
            sys.exit(1)
        else:
            # logger.debug(response)
            result = response.get("results", [])
            logger.info(f"'{len(result)}' events for query '{query}'.")
            return result
    except (botocore.errorfactory.ClientError) as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "NoCredentialsError":
            logger.error(f"Could not find AWS credentials. Error: {str(e)}.")
        elif error_code == "InvalidParameterException":
            logger.error(
                f"Wrong parameters with wuery '{query_id}'. Error: {str(e)}"
            )
        elif error_code == "ResourceNotFoundException":
            logger.error(
                f"Did not find the query '{query_id}'. Error: {str(e)}"
            )
        else:
            logger.error(f"Error: 'str(e)'")
        sys.exit(1)

    print(f"No query result found with log group '{log_group}'")


@init_log_message
def get_logs(
    log_group=LOG_GROUP, log_stream=LOG_STREAM, limit=LIMIT, client=None
):
    try:
        response = client.get_log_events(
            logGroupName=log_group, logStreamName=log_stream, limit=limit
        )
        return response
    except (botocore.errorfactory.ClientError) as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "NoCredentialsError":
            logger.error(f"Could not find AWS credentials. Error: {str(e)}.")
        elif error_code == "InvalidParameterException":
            logger.error(
                f"Wrong parameters with log group '{log_group}' and log stream '{log_stream}'. Error: {str(e)}"
            )
        elif error_code == "ResourceNotFoundException":
            logger.error(
                f"Did not find log group '{log_group}' with log stream '{log_stream}'. Error: {str(e)}"
            )
        else:
            logger.error(f"Error: 'str(e)'")
        sys.exit(1)


def main():
    try:
        from _version import __version__
    except Exception:
        logger.warning("Using developer version.")
        __version__ = "develop"

    parser = argparse.ArgumentParser(
        description="Get AWS Cloudwatch logs.",
        epilog="Example:\npython aws_get_logs.py --region <aws_region> --group <log_group_name> --stream <log_stream_name> --output <output_info>",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s {version}".format(version=__version__),
    )

    # Same for all subcommnds
    config = argparse.ArgumentParser(add_help=False)

    config.add_argument(
        "-r", "--region", default=REGION_DEFAULT, help="AWS region."
    )

    config.add_argument(
        "-g", "--group", default=LOG_GROUP, help="AWS CloudWatch log group."
    )
    config.add_argument(
        "--start-time",
        default=START_TIME_DEFAULT,
        type=int,
        help="AWS CloudWatch log events start time, default value in hours. See '--time-unit'.",
    )
    config.add_argument(
        "--time-unit",
        default=TIME_UNIT_DEFAULT,
        const=TIME_UNIT_DEFAULT,
        nargs="?",
        choices=("hours", "minutes"),
        type=str,
        help="Time unit when processing the value of '--start-time'.",
    )
    config.add_argument(
        "--limit",
        default=LIMIT_DEFAULT,
        type=int,
        help="AWS CloudWatch log events query result limit.",
    )
    config.add_argument(
        "--debug", action="store_true", help="Show debug info."
    )

    subparsers = parser.add_subparsers(
        help="sub-command help", dest="subcommand"
    )
    subparsers.required = True

    # create the parser for the "a" command
    subparsers.add_parser(
        "recent-streams",
        parents=[config],
        help="Get most recent streams from Cloudwatch by a given stream.",
    )

    parser_stream = subparsers.add_parser(
        "get-stream",
        parents=[config],
        help="Get Cloudwatch logs by a given stream.",
    )
    parser_stream.add_argument(
        "-s", "--stream", default=LOG_STREAM, help="AWS CloudWatch log stream."
    )

    parser_follow = subparsers.add_parser(
        "follow-stream",
        parents=[config],
        help="Get Cloudwatch logs by a given stream and follow it.",
    )
    parser_follow.add_argument(
        "-s", "--stream", default=LOG_STREAM, help="AWS CloudWatch log stream."
    )

    parser_insights = subparsers.add_parser(
        "insights",
        parents=[config],
        help="Query Cloudwatch logs with an Insight query. Waits up to 3 minutes for the query to finish.",
    )
    parser_insights.add_argument(
        "-q",
        "--query",
        default=QUERY_DEFAULT,
        help="AWS CloudWatch Insights query to run. Waits up to 3 minutes for the query to finish.",
    )

    args = parser.parse_args()

    get_stream = False
    follow_stream = False
    insights = False
    recent_streams = False

    debug = args.debug
    if debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    region = args.region
    logger.info(f"Working in: {region}")

    session = boto3.session.Session()
    log_client = session.client("logs", region)

    log_group = args.group

    start_time = args.start_time
    time_unit = args.time_unit

    limit = args.limit

    if args.subcommand == "recent-streams":
        recent_streams = True
    elif args.subcommand == "get-stream":
        get_stream = True
        log_stream = args.stream
    elif args.subcommand == "follow-stream":
        follow_stream = True
        log_stream = args.stream
    elif args.subcommand == "insights":
        insights = True
        query = args.query

    if insights:
        result = get_logs_using_insights(
            log_group=log_group,
            start_time_offset=start_time,
            time_unit=time_unit,
            limit=limit,
            query=query,
            client=log_client,
        )
        print(*result, sep="\n")
    elif get_stream:
        try:
            for message in get_logs_filter_streams(
                log_group=log_group,
                log_stream=log_stream,
                start_time_offset=start_time,
                time_unit=time_unit,
                limit=limit,
                follow=False,
                client=log_client,
                debug=debug,
            ):
                print(message)
        except (KeyboardInterrupt):
            print("Stopped.")
    elif follow_stream:
        try:
            for message in get_logs_filter_streams(
                log_group=log_group,
                log_stream=log_stream,
                start_time_offset=start_time,
                time_unit=time_unit,
                limit=limit,
                follow=True,
                client=log_client,
                debug=debug,
            ):
                print(message)
        except (KeyboardInterrupt):
            print("Stopped.")
    elif recent_streams:
        print(
            show_most_recent_log_streams(
                log_group=log_group, client=log_client, debug=debug
            )
        )


if __name__ == "__main__":
    sys.exit(main())
