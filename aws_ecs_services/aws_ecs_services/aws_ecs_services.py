#!/usr/bin/env python

"""
Goal:
  * Get instance information (ip, id, dns) by a service's full DNS name or part of the service's name.
  * List all instance ids in a cluster.
  * list all services in a cluster.

How to:
  * Get help
    - aws_ecs_services.py -h
  * By service DNS name:
    - Getting information by a service's DNS name (AWS Route53), the tool gets the IP from this dns name and searches this IP in the list of private IPs in all the given cluster's instances.
    - aws_ecs_services.py by-service-dns -h
    - python aws_ecs_services.py by-service-dns --region <aws_region> --cluster <ecs_cluster_name> --dns <service_dns_name> --output <output_info>
  * By service name:
    - Getting the instance id by a service's name (ECS service), the tool connects to every cluster instance using AWS SSM (requires 'ssm-agent' on every instance, requires 'AWS Session Manager Plugin' locally) and returns the instance's id if the service can be found. The service is checked using regular expressions, so not the complete service name needs to be known, but the tool stops at the first match.
    - Services are found by checking running docker containerson the instances.
    - aws_ecs_services.py by-service-name -h
    - python aws_ecs_services.py by-service-name --region <aws_region> --cluster <ecs_cluster_name> --name <service_name>
    - The tool also can list every running service running:
    - python aws_ecs_services.py list-services --region <aws_region> --cluster <ecs_cluster_name>
  * List instance ids:
    - It's possible to list every available instance id in the cluster.
    - python aws_ecs_services.py list-instances
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
import socket
import logging
import sys
from time import sleep
import re
from threading import Thread
from queue import Queue

import boto3
import botocore

logging.basicConfig()
logger = logging.getLogger("AwsGetInstance")
logger.setLevel(logging.INFO)

REGION_DEFAULT = "eu-west-1"
OUTPUT_INFO_DEFAULT = "ip"

REGION = os.environ.get("AWS_REGION", REGION_DEFAULT)
CLUSTER_NAME = os.environ.get("CLUSTER_NAME", None)
SERVICE_DNS = os.environ.get("SERVICE_DNS", None)
SERVICE_NAME = os.environ.get("SERVICE_NAME", None)
OUTPUT_INFO = os.environ.get("OUTPUT_INFO", OUTPUT_INFO_DEFAULT)

# By service name
IGNORED_CONTAINERS = ["ecs-agent"]  # Ignored containers
IGNORED_NAMES = ["internalecspause"]  # ignored parts of container names

container_queue = Queue()

# Function to display hostname and
# IP address
def get_host_ip(host_name=""):
    host_ip = ""
    try:
        host_ip = socket.gethostbyname(host_name)
    except (socket.error) as e:
        logger.error(f"Unable to get IP for' {host_name}': {str(e)}")
        sys.exit(1)
    logger.debug(f"IP of {SERVICE_DNS} is {host_ip}")
    return host_ip


def get_instance_ids_from_cluster(cluster=CLUSTER_NAME, client=None):
    logger.info(f"Checking cluster: {cluster}")
    try:
        container_instances = client.list_container_instances(cluster=cluster)[
            "containerInstanceArns"
        ]
        instances = client.describe_container_instances(
            cluster=cluster, containerInstances=container_instances
        )["containerInstances"]
        instance_ids = []
        for instance in instances:
            instance_ids.append(instance.get("ec2InstanceId", None))
        return instance_ids
    except (botocore.exceptions.ClientError) as e:
        if e.response["Error"]["Code"] == "ClusterNotFoundException":
            logger.error(f"Cluster '{cluster}' not found: {str(e)}.")
        else:
            logger.error(f"Error: {str(e)}.")
        sys.exit(1)


def get_instance_info_by_service_dns(
    instance_ids=None, service_ip="", client=None
):
    instance_private_ip = instance_private_dns = instance_id = ""
    if instance_ids and service_ip:
        reservations = client.describe_instances(InstanceIds=instance_ids)[
            "Reservations"
        ]
        for reservation in reservations:
            instances = reservation["Instances"]
            for instance in instances:
                network_interfaces = instance.get("NetworkInterfaces", [])
                for eni in network_interfaces:
                    private_ip_address = eni.get("PrivateIpAddress", None)
                    if service_ip == private_ip_address:
                        instance_private_dns = instance.get(
                            "PrivateDnsName", None
                        )
                        instance_private_ip = instance.get(
                            "PrivateIpAddress", None
                        )
                        instance_id = instance.get("InstanceId", None)
                        break

    return instance_private_ip, instance_private_dns, instance_id


def get_containers(
    instance_id=None, service="", list_services=False, client=None
):
    logger.debug(f"Getting info from instance {instance_id}.")
    try:
        response = client.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={
                "commands": ["sudo docker container ls --format '{{.Names}}'"]
            },
        )
    except (client.exceptions.InvalidInstanceId) as e:
        logger.error(
            f"Instance id '{instance_id}' not found. Is the 'ssm-agent' installed? {str(e)}"
        )
        sys.exit(1)

    command_id = response["Command"]["CommandId"]

    # Get the result of the above command
    retries = 10
    output = None
    status = None
    while retries >= 0:
        retries -= 1
        sleep(1)
        result = client.get_command_invocation(
            InstanceId=instance_id, CommandId=command_id
        )
        output = result["StandardOutputContent"]
        status = result["Status"]

        logger.debug(
            f"Waiting for instance '{instance_id}' response. Status is '{status}'."
        )

        # Possible values for 'Status'
        # 'Pending'|'InProgress'|'Delayed'|'Success'|'Cancelled'|'TimedOut'|'Failed'|'Cancelling'
        # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ssm.html#SSM.Client.get_command_invocation
        if status == "Success":
            break

    if not status == "Success":
        logger.warning(
            f"Could not contact instance '{instance_id}', status is '{status}'. Is something wrong?"
        )
        return

    for container_name in output.split():
        ignore_container = False
        if container_name not in IGNORED_CONTAINERS:
            logger.debug(
                f"Checking container '{container_name}' on instance '{instance_id}'."
            )
            if not list_services:
                if re.search(service, container_name):
                    logger.info(
                        f"Instance '{instance_id}' runs container '{container_name}'."
                    )
                    container_queue.put(instance_id)
                    break
            else:
                for ignored_name in IGNORED_NAMES:
                    if re.search(ignored_name, container_name):
                        ignore_container = True
                if not ignore_container:
                    container_queue.put(container_name)

    return container_queue.qsize()


def get_instance_id_by_service_name(
    region=REGION,
    instance_ids=None,
    service="",
    list_services=False,
    client=None,
):
    if list_services:
        logger.info(f"List all deployed/running services.")
    else:
        logger.info(f"Get instance of service '{service}'.")

    container_names = []

    if list_services:
        threads = []

    for instance_id in instance_ids:
        if list_services:
            # It's to start threads, since we need to check all instances.
            thread = Thread(
                target=get_containers,
                kwargs={
                    "instance_id": instance_id,
                    "service": service,
                    "list_services": list_services,
                    "client": client,
                },
            )
            thread.daemon = True
            thread.start()
            threads.append(thread)
        else:
            # Not using threaded approach, since the loop is exited as soon as the service is found.
            if get_containers(
                instance_id=instance_id,
                service=service,
                list_services=list_services,
                client=client,
            ):
                break

    if list_services:
        for thread in threads:
            thread.join()  # wait for end of threads

    while not container_queue.empty():
        container_names.append(container_queue.get())
        container_queue.task_done()

    if not container_names and not list_services:
        logger.error(f"Service '{service}' not found.")
    else:
        print("\n".join(container_names))


def main():
    """

    """

    from _version import __version__

    parser = argparse.ArgumentParser(
        description="Get ECS service info (e.g. EC2 instacne id) by a given service name.",
        epilog="Example:\npython aws_ecs_services.py by-service-dns --region <aws_region> --cluster <ecs_cluster_name> --dns <service_dns_name> --output <output_info>",
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
        "-c",
        "--cluster",
        required=True,
        help="AWS ECS cluster to get instances from.",
    )
    config.add_argument(
        "--debug", action="store_true", help="Show debug info."
    )

    subparsers = parser.add_subparsers(
        help="sub-command help", dest="subcommand"
    )
    subparsers.required = True

    # create the parser for the "a" command
    parser_dns = subparsers.add_parser(
        "by-service-dns",
        parents=[config],
        help="Get instance information by service's dns name.",
    )
    parser_dns.add_argument(
        "-d",
        "--dns",
        required=True,
        help="DNS name of the service to find the instance for.",
    )
    parser_dns.add_argument(
        "-o",
        "--output",
        nargs="?",
        default=OUTPUT_INFO_DEFAULT,
        choices=["ip", "id", "all", "service"],
        help="Information to return to the user. 'ip' returns the instance's private IP. 'id' returns the instance's id. 'all' returns the former and the private DNS. 'service' returns the service's IP only.",
    )

    # By service name
    parser_name = subparsers.add_parser(
        "by-service-name",
        parents=[config],
        help="Get instance id by service's name.",
    )
    name_action = parser_name.add_mutually_exclusive_group(required=True)
    name_action.add_argument(
        "-n",
        "--name",
        default="",
        help="Name of the service to find the instance for.",
    )

    # Return all cluster instances
    subparsers.add_parser(
        "list-instances", parents=[config], help="Get all cluster instances.",
    )

    # Return all cluster services
    subparsers.add_parser(
        "list-services",
        parents=[config],
        help="Get all active cluster services.",
    )

    args = parser.parse_args()

    by_service_dns = False
    by_service_name = False
    only_instance_ids = False
    list_services = False

    debug = args.debug
    if debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    region = args.region
    logger.info(f"Working in: {region}")

    cluster_name = args.cluster

    session = boto3.session.Session()
    ecs_client = session.client("ecs", region)
    ec2_client = session.client("ec2", region)
    ssm_client = session.client("ssm", region)

    if args.subcommand == "by-service-dns":
        by_service_dns = True
        service_dns = args.dns
        output_info = args.output
    elif args.subcommand == "by-service-name":
        by_service_name = True
        service_name = args.name
    elif args.subcommand == "list-instances":
        only_instance_ids = True
    elif args.subcommand == "list-services":
        list_services = True
        service_name = None

    if only_instance_ids:
        instance_ids = get_instance_ids_from_cluster(
            cluster=cluster_name, client=ecs_client
        )
        print(" ".join(instance_ids))
        return
    elif by_service_name or list_services:
        instance_ids = get_instance_ids_from_cluster(
            cluster=cluster_name, client=ecs_client
        )
        instance_id = get_instance_id_by_service_name(
            region=region,
            instance_ids=instance_ids,
            service=service_name,
            list_services=list_services,
            client=ssm_client,
        )
        return
    elif by_service_dns:
        service_ip = get_host_ip(host_name=service_dns)
        if output_info == "service":
            print(service_ip)
            return
        else:
            instance_ids = get_instance_ids_from_cluster(
                cluster=cluster_name, client=ecs_client
            )
            (
                instance_private_ip,
                instance_private_dns,
                instance_id,
            ) = get_instance_info_by_service_dns(
                instance_ids=instance_ids,
                service_ip=service_ip,
                client=ec2_client,
            )
            if output_info == "ip":
                print(instance_private_ip)
                return
            elif output_info == "id":
                print(instance_id)
                return
            elif output_info == "all":
                print(instance_private_ip, instance_id, instance_private_dns)
                return
    logger.error(f"Not the expected result - nothing accomplished.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
