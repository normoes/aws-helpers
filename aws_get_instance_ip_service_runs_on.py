#!/usr/bin/env python

import os
import argparse
import boto3
import socket
import logging


"""
Goal:
  * Get the private ip of the instance the given service is running on (deployed with AWS ECS).

How to:
  * Get help
    - aws-ecs-get-service-instance.py -h
  * The tool works with the service's DNS name. It gets the IP from this dns name and searches this IP in the list of private IPs in all the given cluster's instances.
  * The tool should be used in combination with aws-vault. It uses boto3 and only works with valid AWS credentials.
  * The AWS region can be given as environemnt variable REGION
    - REGION=eu-west-2 python aws_get_instance_ip_service_runs_on.py
  * The AWS region can be given as argument (-r, --region)
    - python aws_get_instance_ip_service_runs_on.py --region <aws_region> --cluster <ecs_cluster_name> --dns <service_dns_name>
  * If the AWS region is set both ways, REGION has precedence.
  * The ECS cluster can be given as environemnt variable CLUSTER_NAME
  * The ECS cluster can be given as argument (-c, --cluster)
  * If the ECS cluster is set both ways, CLUSTER_NAME has precedence.
  * The service's dns name can be given as environemnt variable SERVICE_DNS
  * The service's dns name can be given as argument (-d, --dns)
  * If the service's dns name  is set both ways, SERVICE_DNS has precedence.
"""


logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

REGION = os.environ.get("REGION", None)
CLUSTER_NAME = os.environ.get("CLUSTER_NAME", None)
SERVICE_DNS = os.environ.get("SERVICE_DNS", None)

parser = argparse.ArgumentParser(
    description="Get most recent tags in group repositories.", formatter_class=argparse.ArgumentDefaultsHelpFormatter
)
parser.add_argument(
    "-r", "--region", required=True, default="eu-west-1", help="AWS region."
)
parser.add_argument(
    "-c", "--cluster", required=True, default="ecs_cluster_name", help="AWS ECS cluster to get instances from."
)
parser.add_argument(
    "-d", "--dns", required=True, default="service.dns.name", help="DNS name of the service to find the instance for."
)
args = parser.parse_args()

if not REGION:
    REGION = args.region

if not CLUSTER_NAME:
    CLUSTER_NAME = args.cluster

if not SERVICE_DNS:
    SERVICE_DNS = args.dns

crypto = boto3.session.Session()
ecs_client = crypto.client("ecs", REGION)
ec2_client = crypto.client("ec2", REGION)


# Function to display hostname and
# IP address
def get_host_ip(host_name=""):
    try:
        host_ip = socket.gethostbyname(host_name)
        return host_ip
    except (socket.error) as e:
        print(f"Unable to get IP: {str(e)}")


def get_instance_ids_from_cluster(cluster=""):
    container_instances = ecs_client.list_container_instances(cluster=cluster)[
        "containerInstanceArns"
    ]
    instances = ecs_client.describe_container_instances(
        cluster=cluster, containerInstances=container_instances
    )["containerInstances"]
    instance_ids = list()
    for instance in instances:
        instance_ids.append(instance.get("ec2InstanceId", None))
    return instance_ids


def get_private_ip_dns(instance_ids=None, service_ip=""):
    instance_private_ip = instance_private_dns = instance_id = ""
    if instance_ids and service_ip:
        reservations = ec2_client.describe_instances(InstanceIds=instance_ids)[
            "Reservations"
        ]
        for reservation in reservations:
            instances = reservation["Instances"]
            for instance in instances:
                network_interfaces = instance.get("NetworkInterfaces", list())
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


if __name__ == "__main__":
    service_ip = get_host_ip(host_name=SERVICE_DNS)
    # print(f"IP of {host_name} is {service_ip}")
    instance_ids = get_instance_ids_from_cluster(cluster=CLUSTER_NAME)
    instance_private_ip, instance_private_dns, instance_id = get_private_ip_dns(
        instance_ids=instance_ids, service_ip=service_ip
    )
    # print(f"{host_name} is running on {instance_id}")
    # print(f"  private ip: {instance_private_ip}")
    # print(f"  private dns: {instance_private_dns}")
    print(instance_private_ip)
