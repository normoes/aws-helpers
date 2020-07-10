import logging
import argparse
import boto3
from botocore.exceptions import ClientError


logging.basicConfig()
logger = logging.getLogger(__name__)


AWS_REGION_DEFAULT = "eu-west-1"


def force_restart_service(cluster, service, region=AWS_REGION_DEFAULT):
    session = boto3.session.Session()
    ecs_client = session.client("ecs", region)
    services = ((f"{cluster}", f"{service}"),)

    for cluster, service in services:
        logger.info(f"Restarting service '{service}' in cluster '{cluster}'.")
        try:
            ecs_client.update_service(
                cluster=cluster, service=service, forceNewDeployment=True
            )
        except (ClientError) as e:
            logger.error(
                f"Error restarting service '{service}' in cluster '{cluster}': {e.response['Error']['Code']}."
            )


def main():
    parser = argparse.ArgumentParser(
        description="Force the restart of ECS services in the xmrto project.",
        epilog="Example:\npython force_restart_services.py --region <aws_region> --cluster=<cluster_name> --service=<service_name>",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "-r", "--region", default=AWS_REGION_DEFAULT, help="AWS region."
    )
    # 'project' and 'environment' build a prefix used fortheservice name: f"{project}-{environment}" ("project2-staging")
    # Also this prefix is the name of the ECS cluster.
    parser.add_argument("-c", "--cluster", default="", help="ECS cluster.")
    parser.add_argument("-s", "--service", default="", help="ECS service.")
    parser.add_argument(
        "--debug", action="store_true", help="Show debug info."
    )

    args = parser.parse_args()

    debug = args.debug
    if debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    region = args.region
    cluster = args.cluster
    service = args.service

    force_restart_service(region=region, cluster=cluster, service=service)


if __name__ == "__main__":
    main()
