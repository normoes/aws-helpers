#!/usr/bin/env python

"""
Goal:
  * Get Cloudwatch logs.

How to:
  * Get help
    - aws_get_logs.py -h
  * By service DNS name:
    - Getting information by a service's DNS name (AWS Route53), the tool gets the IP from this dns name and searches this IP in the list of private IPs in all the given cluster's instances.
    - aws_get_instance_service_runs_on.py by-service-dns -h
    - python aws_get_instance_service_runs_on.py by-service-dns --region <aws_region> --cluster <ecs_cluster_name> --dns <service_dns_name> --output <output_info>
  * By service name:
    - Getting the instance id by a service's name (ECS service), the tool connects to every cluster instance using AWS SSM (requires 'ssm-agent' on every instance, requires 'AWS Session Manager Plugin' locally) and returns the instance's id if the service can be found. The service is checked using regular expressions, so not the complete service name needs to be known, but the tool stops at the first match.
    - Services are found by checking running docker containerson the instances.
    - aws_get_instance_service_runs_on.py by-service-name -h
    - python aws_get_instance_service_runs_on.py by-service-name --region <aws_region> --cluster <ecs_cluster_name> --name <service_name>
    - The tool also can list every running service running:
    - python aws_get_instance_service_runs_on.py by-service-name --region <aws_region> --cluster <ecs_cluster_name> --list
  * List instance ids:
    - It's possible to list every available instance id in the cluster.
    - python aws_get_instance_service_runs_on.py instance-ids
  * The tool should be used in combination with aws-vault. It uses boto3 and only works with valid AWS credentials.
  * The AWS region can be given as environemnt variable REGION
  * The AWS region can be given as argument (-r, --region)
  * If the AWS region is set both ways, REGION has precedence.
  * The ECS cluster can be given as environemnt variable CLUSTER_NAME
  * The ECS cluster can be given as argument (-c, --cluster)
  * If the ECS cluster is set both ways, CLUSTER_NAME has precedence.
  * The service's dns name can be given as environemnt variable SERVICE_DNS
  * The service's dns name can be given as argument (-d, --dns)
  * If the service's dns name is set both ways, SERVICE_DNS has precedence.
  * The oputput info can be given as environemnt variable OUTPUT_INFO
  * The output info can be given as argument (-o, --output)
  * If the output info  is set both ways, OUTPUT_INFO has precedence.
  * The service's name can be given as environemnt variable SERVICE_NAME
  * The service's name can be given as argument (-n, --name)
  * If the service's name is set both ways, SERVICE_NAME has precedence.
"""

import os
import argparse
import boto3
import botocore
import socket
import logging
import sys
import functools
import json
from time import sleep
import re
from datetime import datetime, timedelta
from collections import defaultdict

logging.basicConfig()
logger = logging.getLogger("AWSGetLogs")
logger.setLevel(logging.INFO)

REGION_DEFAULT = "eu-west-1"
START_TIME_DEFAULT = 3
LIMIT_DEFAULT = 20
QUERY_DEFAULT = "fields @timestamp, @message | sort @timestamp desc | limit 20"

REGION = os.environ.get("AWS_REGION", REGION_DEFAULT)
LOG_GROUP = os.environ.get("LOG_GROUP", None)
LOG_STREAM = os.environ.get("LOG_STREAM", None)
START_TIME = os.environ.get("START_TIME", START_TIME_DEFAULT)
LIMIT = os.environ.get("LIMIT", LIMIT_DEFAULT)
QUERY = os.environ.get("QUERY", QUERY_DEFAULT)


def init_log_message(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time_offset = kwargs.get("start_time_offset", None)
        limit = kwargs.get("limit", None)
        logger.info(f"Going '{start_time_offset} hours' back in time.")
        logger.info(f"Limiting results to '{limit}'.")
        return func(*args, **kwargs)
    return wrapper
    

def make_time(start_time_offset:int=0):
    """Create query start and end times.

    The end_time is now.
    The start_time is derived from end_time andagiven number of hours to go back in time.

    For now any given value is considered to represent hours.
    """

    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=start_time_offset)
    end_time = int(datetime.timestamp(end_time)) * 1000
    start_time = int(datetime.timestamp(start_time) * 1000)
    return start_time, end_time


@init_log_message
def show_most_recent_log_streams(log_group=LOG_GROUP, client=None):
    next_token = "first"
    parameters = {"logGroupName": log_group, "orderBy":"LastEventTime"}
    most_recent_log_streams = list()
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
                print(f"nextToken: {next_token}")
                log_streams = response.get("logStreams", list())
                for log_stream in log_streams:
                    log_stream_name = log_stream.get("logStreamName", None)
                    if log_stream_name and not log_stream_name in most_recent_log_streams:
                        most_recent_log_streams.append(log_stream_name)
                print(json.dumps(response, indent=4))
            else:
                print(f"No response received")
        except (client.exceptions.InvalidParameterException) as e:
            logger.error(f"Wrong parameters with log group '{log_group}'. Error: {str(e)}")
            sys.exit(1)
        except (client.exceptions.ResourceNotFoundException) as e:
            logger.error(f"Did not find log group '{log_group}'. Error: {str(e)}")
            sys.exit(1)
    print(f"No streams found with log group '{log_group}'")
            

@init_log_message
def get_logs_filter_streams(log_group=LOG_GROUP, log_stream=LOG_STREAM, limit=LIMIT, start_time_offset=START_TIME, client=None, debug=False):
    next_token = "first"
    start_time, end_time = make_time(start_time_offset)
    parameters = {"logGroupName": log_group, "logStreamNamePrefix": log_stream, "limit": limit, "startTime": start_time, "endTime": end_time}
    timestamps = list()
    searched_log_streams = list()
    while next_token:
        try:
            response = client.filter_log_events(**parameters)
            print(json.dumps(response, indent=4))

            if response:
                log_streams = response.get("searchedLogStreams", dict())
                searched_log_streams.append(log_streams)
                next_token = response.get("nextToken", "")
                if next_token:
                    parameter_next_token = {"nextToken": next_token}
                    parameters.update(parameter_next_token)
                else:
                    parameters.pop("nextToken", None)
                # print(f"nextToken: {next_token}")
                log_events = response.get("events", list())
                # print(len(log_events))
                for log_event in log_events:
                    log_stream_name = log_event.get("logStreamName", None)
                    timestamps.append(log_event.get("timestamp", -1))
                    {"timestamp":log_event.get("timestamp", -1), "message": log_event.get("message", "")}
                    # most_recent_logs[log_stream_name].append({"timestamp":log_event.get("timestamp", -1), "message": log_event.get("message", "")})
        except (client.exceptions.InvalidParameterException) as e:
            logger.error(f"Wrong parameters with log group '{log_group}'. Error: {str(e)}")
            sys.exit(1)
        except (client.exceptions.ResourceNotFoundException) as e:
            logger.error(f"Did not find log group '{log_group}'. Error: {str(e)}")
            sys.exit(1)

    if debug:
       if timestamps:
           sorted_timestamps = sorted(timestamps)
           print(f"given start_time '{datetime.fromtimestamp(start_time/1000)}' :: first log event at '{datetime.fromtimestamp(sorted_timestamps[0]/1000)}'")
           print(f"given end_time '{datetime.fromtimestamp(end_time/1000)}' :: last log event at '{datetime.fromtimestamp(sorted_timestamps[-1]/1000)}'")
       if searched_log_streams:
           print(searched_log_streams)
    print()
            

@init_log_message
def get_logs_filter_streams_follow(log_group=LOG_GROUP, log_stream=LOG_STREAM, limit=LIMIT, start_time_offset=START_TIME, client=None, debug=False):
    next_token = "first"
    start_time, end_time = make_time(start_time_offset)
    parameters = {"logGroupName": log_group, "logStreamNamePrefix": log_stream, "limit": limit, "startTime": start_time, "endTime": end_time}
    timestamps = list()
    searched_log_streams = list()
    while True:
        try:
            response = client.filter_log_events(**parameters)
            # print(json.dumps(response, indent=4))

            if response:
                log_streams = response.get("searchedLogStreams", dict())
                searched_log_streams.append(log_streams)
                next_token = response.get("nextToken", "")
                if next_token:
                    parameter_next_token = {"nextToken": next_token}
                    parameters.update(parameter_next_token)
                else:
                    parameters.pop("nextToken", None)
                log_events = response.get("events", list())
                for log_event in log_events:
                    log_stream_name = log_event.get("logStreamName", None)
                    timestamp = log_event.get("timestamp", -1)
                    message = log_event.get("message", "")
                    print(message)
        except (botocore.errorfactory.ClientError) as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "InvalidParameterException":
                logger.error(f"Wrong parameters with log group '{log_group}'. Error: {str(e)}.")
                sys.exit(1)
            elif error_code == "ResourceNotFoundException":
                logger.error(f"Did not find log group '{log_group}'. Error: {str(e)}.")
                sys.exit(1)


@init_log_message
def get_logs_using_insights(log_group=LOG_GROUP, query=QUERY, limit=LIMIT, start_time_offset=START_TIME, client=None):
    start_time, end_time = make_time(start_time_offset)
    parameters = {"logGroupName": log_group, "startTime": start_time, "endTime": end_time, "queryString": query, "limit": limit}
    most_recent_log_streams = list()
    logger.info(f"Starting query '{parameters['queryString']}'")
    query_id = ""
    result = list()
    try:
        response = client.start_query(**parameters)
        if response:
            log_streams = response.get("logStreams", list())
            for log_stream in log_streams:
                log_stream_name = log_stream.get("logStreamName", None)
                if log_stream_name and not log_stream_name in most_recent_log_streams:
                    most_recent_log_streams.append(log_stream_name)
            # print(json.dumps(response, indent=4))

            query_id = response.get("queryId", "")
        else:
            print(f"No response received")
    except (botocore.errorfactory.ClientError) as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "MalformedQueryException":
            logger.error(f"Error in query '{parameters['queryString']}'. Error: {str(e)}")
            sys.exit(1)
        elif error_code == "InvalidParameterException":
            logger.error(f"Wrong parameters with log group '{log_group}'. Error: {str(e)}")
            sys.exit(1)
        elif error_code == "ResourceNotFoundException":
            logger.error(f"Did not find log group '{log_group}'. Error: {str(e)}")
            sys.exit(1)
        logger.error(f"Error 'str(e)'")

    status = ""
    try:
        logger.debug(f"Checking query '{query_id}'")
        retries = 180
        while retries >= 0:
        # while not status == "Complete":
            retries -= 1
            sleep(1)
            response = client.get_query_results(
                queryId=query_id
            )
            # print(json.dumps(response, indent=4))

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
            result = response.get("results", list())
            logger.info(f"Number of of events: '{len(result)}'")
            return result
    except (botocore.errorfactory.ClientError) as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "InvalidParameterException":
            logger.error(f"Wrong parameters with log group '{log_group}'. Error: {str(e)}")
            sys.exit(1)
        elif error_code == "ResourceNotFoundException":
            logger.error(f"Did not find log group '{log_group}'. Error: {str(e)}")
            sys.exit(1)
        logger.error(f"Error 'str(e)'")

    print(f"No query result found with log group '{log_group}'")
            

@init_log_message
def get_logs(log_group=LOG_GROUP, log_stream=LOG_STREAM, limit=LIMIT, client=None):
    try:
        response = client.get_log_events(
            logGroupName=log_group,
            logStreamName=log_stream,
        )
        return response
    except (client.exceptions.InvalidParameterException) as e:
        logger.error(f"Wrong parameters with log group '{log_group}' and log stream '{log_stream}'. Error: {str(e)}")
        sys.exit(1)
    except (client.exceptions.ResourceNotFoundException) as e:
        logger.error(f"Did not find log group '{log_group}' with log stream '{log_stream}'. Error: {str(e)}")
        sys.exit(1)

def main():
    try:
        from _version import __version__
    except:
        __version__ = "develop"

    parser = argparse.ArgumentParser(
        description="Get AWS Cloudwatch logs.", epilog="Example:\npython aws_get_logs.py --region <aws_region> --group <log_group_name> --stream <log_stream_name> --output <output_info>", formatter_class=argparse.ArgumentDefaultsHelpFormatter
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
        "-g", "--group", required=True, help="AWS CloudWatch log group."
    )
    config.add_argument(
        "--start-time", default=START_TIME_DEFAULT, type=int, help="AWS CloudWatch log events start time, for now in hours only."
    )
    config.add_argument(
        "--limit", default=LIMIT_DEFAULT, type=int, help="AWS CloudWatch log events query result limit."
    )
    config.add_argument(
        "--debug", action='store_true',  help="Show debug info."
    )

    subparsers = parser.add_subparsers(help='sub-command help', dest='subcommand')
    subparsers.required = True

    # create the parser for the "a" command
    parser_stream = subparsers.add_parser('filter-stream', parents=[config], help="Get Cloudwatch logs by a given stream.")
    parser_stream.add_argument(
        "-s", "--stream", required=True, help="AWS CloudWatch log stream."
    )

    parser_stream = subparsers.add_parser('follow-stream', parents=[config], help="Get Cloudwatch logs by a given stream and follow it.")
    parser_stream.add_argument(
        "-s", "--stream", required=True, help="AWS CloudWatch log stream."
    )

    parser_insights = subparsers.add_parser('insights', parents=[config], help="Query Cloudwatch logs with an Insight query. Waits up to 3 minutes for the query to finish.")
    parser_insights.add_argument(
        "-q", "--query", default=QUERY_DEFAULT, help="AWS CloudWatch Insights query to run. Waits up to 3 minutes for the query to finish."
    )
    
    args = parser.parse_args()
   
    filter_stream = False
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

    if LOG_GROUP:
        log_group = LOG_GROUP
    else:
        log_group = args.group

    start_time = args.start_time

    limit = args.limit
    
    if args.subcommand == "filter-stream":
        filter_stream = True
        if LOG_STREAM:
            log_stream = LOG_STREAM
        else:
            log_stream = args.stream
    
    if args.subcommand == "follow-stream":
        follow_stream = True
        if LOG_STREAM:
            log_stream = LOG_STREAM
        else:
            log_stream = args.stream
    
    if args.subcommand == "insights":
        insights = True
        query = args.query
    # if debug:
    #     show_most_recent_log_streams(log_group=log_group, client=log_client)
    # print(get_logs(log_group=log_group, log_stream=log_stream, client=log_client))
    if insights:
        result = get_logs_using_insights(log_group=log_group, start_time_offset=start_time, limit=limit, query=query, client=log_client)
        print(*result, sep = "\n")
    elif filter_stream:
        print(get_logs_filter_streams(log_group=log_group, log_stream=log_stream, start_time_offset=start_time, limit=limit, client=log_client, debug=debug))
    elif follow_stream:
        try:
            get_logs_filter_streams_follow(log_group=log_group, log_stream=log_stream, start_time_offset=start_time, limit=limit, client=log_client, debug=debug)
        except (KeyboardInterrupt) as e:
            print("Stopped.")
    elif recent_streams:
        print(show_most_recent_log_streams(log_group=log_group, log_stream=log_stream, start_time_offset=start_time, limit=limit, client=log_client, debug=debug))



if __name__ == "__main__":
    sys.exit(main())
