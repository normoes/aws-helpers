import logging
import argparse
from collections import defaultdict
import sys

import boto3
from botocore.exceptions import ClientError


logging.basicConfig()
logger = logging.getLogger(__name__)


AWS_REGION_DEFAULT = "eu-west-1"


def update_ecs_agents(
    region=AWS_REGION_DEFAULT, list_clusters=False, list_container_instances=False,
):
    """Update all the containers' ecs agents.

    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ecs.html#ECS.Client.update_container_agent

    aws-vault-css-sideprojects -- aws ecs update-container-agent --cluster aeond --container-instance 3414b292-716f-4aa3-ae15-1e16c7c418a0
    """

    session = boto3.session.Session()
    ecs_client = session.client("ecs", region)

    # Get all clusters.
    # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ecs.html#ECS.Client.list_container_instances
    response = ecs_client.list_clusters()
    clusters = response["clusterArns"]
    if list_clusters:
        logger.info(f"Showing all available clusters.")
        print(*clusters)
        return

    # Get all container instances in the clusters.
    container_instances = defaultdict(list)
    for cluster in clusters:
        response = ecs_client.list_container_instances(
            cluster=cluster, status="ACTIVE",
        )
        container_instances[cluster].extend(response["containerInstanceArns"])

    if list_container_instances:
        logger.info(f"Showing all available container instances in all the clusters.")
        for cluster in clusters:
            print(f"{cluster}: {container_instances[cluster]}")
        return

    for cluster in clusters:
        logger.info(f"Updating ecs agents in cluster '{cluster}'.")
        for container_instance in container_instances[cluster]:
            logger.info(f"Updating container instance '{container_instance}'.")
            try:
                response = ecs_client.update_container_agent(
                    cluster=cluster, containerInstance=container_instance,
                )
                logger.info(f"Updated container instance '{container_instance}'.")
                print(
                    f"  Old agent version: {response['containerInstance']['versionInfo']['agentVersion']}."
                )
                print(
                    f"  Docker version: {response['containerInstance']['versionInfo']['dockerVersion']}."
                )
                print(
                    f"  Agent connected: {response['containerInstance']['agentConnected']}."
                )
                print(
                    f"  Agent update status: {response['containerInstance']['agentUpdateStatus']}."
                )
                print(
                    f"  Running tasks count: {response['containerInstance']['runningTasksCount']}."
                )
                print(
                    f"  Pending tasks count: {response['containerInstance']['pendingTasksCount']}."
                )
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoUpdateAvailableException":
                    logger.warning(
                        f"No update available for container_instance '{container_instances}' in cluster '{cluster}'."
                    )
                else:
                    raise e


def main():
    parser = argparse.ArgumentParser(
        description="Update the ECS agent on all available container instances in all the clusters.",
        epilog="Example:\npython update_ecs_agents.py --region <aws_region>",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "-r", "--region", default=AWS_REGION_DEFAULT, help="AWS region."
    )
    parser.add_argument(
        "--list-clusters",
        action="store_true",
        help="List all clusters. No ecs agent update.",
    )
    parser.add_argument(
        "--list-container-instances",
        action="store_true",
        help="List all container instances. No ecs agent update.",
    )
    parser.add_argument("--debug", action="store_true", help="Show debug info.")

    args = parser.parse_args()

    debug = args.debug
    if debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    region = args.region
    list_clusters = args.list_clusters
    list_container_instances = args.list_container_instances

    return update_ecs_agents(
        region=region,
        list_clusters=list_clusters,
        list_container_instances=list_container_instances,
    )


if __name__ == "__main__":
    sys.exit(main())
