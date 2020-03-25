#!/usr/bin/env python

"""
Goal:
  * Get instance information (ip, id, dns) by a service's full DNS name or part of the service's name.
  * List all instance ids in a cluster.
  * list all services in a cluster.

How to:
  * Get help
    - aws_get_instance_service_runs_on.py -h
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
    - python aws_get_instance_service_runs_on.py list-services --region <aws_region> --cluster <ecs_cluster_name>
  * List instance ids:
    - It's possible to list every available instance id in the cluster.
    - python aws_get_instance_service_runs_on.py list-instances
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
import logging
import sys
from base64 import b64encode, b64decode

import boto3
import botocore

logging.basicConfig()
logger = logging.getLogger("AwsKMSKeys")
logger.setLevel(logging.INFO)

REGION_DEFAULT = "eu-west-1"
EXCLUDE_AWS_ALIAS_DEFAULT = (False,)

REGION = os.environ.get("AWS_REGION", REGION_DEFAULT)

# List keys.
IGNORED_ALIASES = ["alias/aws/"]  # Ignored KMS key aliases


def get_kms_keys(exclude_aws_alias=False, client=None):
    logger.info(f"Getting allthe keys.")

    keys = {}

    try:
        keys = client.list_keys()["Keys"]
    except (botocore.exceptions.ClientError) as e:
        if e.response["Error"]["Code"] == "KMSInternalException":
            logger.error(f"No KMS keys found: {str(e)}.")
        else:
            logger.error(f"Error: {str(e)}.")

    keys_ = list(keys)
    for key in keys_:
        try:
            key_id = key["KeyId"]
            key_arn = key.get("KeyArn", "")
            aliases = client.list_aliases(KeyId=key_id)["Aliases"]
            if exclude_aws_alias:
                for alias in aliases:
                    alias_name = alias["AliasName"]
                    for ignored_alias in IGNORED_ALIASES:
                        if alias_name.startswith(ignored_alias):
                            keys.remove(key)
                            break

            key.update({"Aliases": aliases})
        except (botocore.exceptions.ClientError) as e:
            if e.response["Error"]["Code"] == "KMSInternalException":
                logger.error(f"No KMS keys found: {str(e)}.")
            elif e.response["Error"]["Code"] == "NotFoundException":
                logger.error(f"An alias for key '{key_id}' was not found: {str(e)}.")
            elif e.response["Error"]["Code"] == "InvalidArnException":
                logger.error(
                    f"The given ARN '{key_arn}' for the key '{key_id}' is not valid: {str(e)}."
                )
            else:
                logger.error(f"Error: {str(e)}.")

    return keys


def encrypt_plain(plain="", key_id="", client=None):
    data = {"Plaintext": plain, "KeyId": key_id}

    cipher = "Cannot encrypt."
    try:
        cipher = client.encrypt(**data)["CiphertextBlob"]
    except (botocore.exceptions.ClientError) as e:
        if not key_id:
            key_id = "default"
        if e.response["Error"]["Code"] == "DisabledException":
            logger.error(f"The key '{key_id}' is disabled: {str(e)}.")
        elif e.response["Error"]["Code"] == "InvalidKeyUsageException":
            logger.error(f"Wrong use of key '{key_id}': {str(e)}.")
        elif e.response["Error"]["Code"] == "NotFoundException":
            logger.error(f"The key '{key_id}' was not found: {str(e)}.")
        elif e.response["Error"]["Code"] == "KeyUnavailableException":
            logger.error(f"The key '{key_id}' is unavailable: {str(e)}.")
        elif e.response["Error"]["Code"] == "KMSInternalException":
            logger.error(f"No KMS keys found: {str(e)}.")
        else:
            logger.error(f"Error: {str(e)}.")
        sys.exit(1)

    return b64encode(cipher).decode("utf-8")


def decrypt_cipher(cipher="", key_id="", client=None):

    cipher = b64decode(cipher.encode("utf-8"))

    # Missing: 'EncryptionAlgorithm', default is 'SYMMETRIC_DEFAULT'.
    data = {"CiphertextBlob": cipher, "KeyId": key_id}

    plain = "Cannot decrypt."
    try:
        plain = client.decrypt(**data)["Plaintext"]
    except (botocore.exceptions.ClientError) as e:
        if not key_id:
            key_id = "default"
        if e.response["Error"]["Code"] == "DisabledException":
            logger.error(f"The key '{key_id}' is disabled: {str(e)}.")
        elif e.response["Error"]["Code"] == "InvalidKeyUsageException":
            logger.error(f"Wrong use of key '{key_id}': {str(e)}.")
        elif e.response["Error"]["Code"] == "NotFoundException":
            logger.error(f"The key '{key_id}' was not found: {str(e)}.")
        elif e.response["Error"]["Code"] == "KeyUnavailableException":
            logger.error(f"The key '{key_id}' is unavailable: {str(e)}.")
        elif e.response["Error"]["Code"] == "KMSInternalException":
            logger.error(f"No KMS keys found: {str(e)}.")
        else:
            logger.error(f"Error: {str(e)}.")
        sys.exit(1)

    return plain.decode("utf-8")


def main():
    """

    """

    from _version import __version__

    parser = argparse.ArgumentParser(
        description="Interact with AWS KMS keys.",
        epilog="Example:\npython aws_kms_keys.py encrypt --region <aws_region>  --plain <text_to_encrypt> --key-id=<key_id>",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s {version}".format(version=__version__),
    )

    # Same for all subcommnds
    config = argparse.ArgumentParser(add_help=False)

    config.add_argument("-r", "--region", default=REGION_DEFAULT, help="AWS region.")
    config.add_argument("--debug", action="store_true", help="Show debug info.")

    subparsers = parser.add_subparsers(help="sub-command help", dest="subcommand")
    subparsers.required = True

    # create the parser for the "a" command
    list_keys = subparsers.add_parser(
        "list-keys", parents=[config], help="List AWS CMK KMS keys.",
    )
    list_keys.add_argument(
        "--exclude-aws-alias",
        action="store_true",
        help="Excludes aliases starting with 'alias/aws/'.",
    )

    # Encrypt.
    encrypt = subparsers.add_parser(
        "encrypt", parents=[config], help="Encrypt using an AWS KMS key.",
    )
    encrypt.add_argument(
        "--plain", required=True, help="Plain text to be encrypted.",
    )
    encrypt.add_argument(
        "--key-id", default="", required=True, help="KMD key id to use for encryption.",
    )

    # Decrypt.
    decrypt = subparsers.add_parser(
        "decrypt", parents=[config], help="Decrypt using an AWS KMS key.",
    )
    decrypt.add_argument(
        "--cipher",
        required=True,
        help="Cipher text to be decrypted, in the format: 'AQICAHjXDZ...'.",
    )
    decrypt.add_argument(
        "--key-id", default="", required=True, help="KMD key id to use for decryption.",
    )

    args = parser.parse_args()

    list_keys = False
    exclude_aws_alias = False
    encrypt = False
    decrypt = False

    debug = args.debug
    if debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    region = args.region
    logger.info(f"Working in: {region}")

    session = boto3.session.Session()
    kms_client = session.client("kms", region)

    if args.subcommand == "list-keys":
        list_keys = True
        exclude_aws_alias = args.exclude_aws_alias
    elif args.subcommand == "encrypt":
        encrypt = True
        plain = args.plain
        key_id = args.key_id
    elif args.subcommand == "decrypt":
        decrypt = True
        cipher = args.cipher
        key_id = args.key_id

    if list_keys:
        keys = get_kms_keys(exclude_aws_alias=exclude_aws_alias, client=kms_client)
        print(keys)
        return
    elif encrypt:
        cipher = encrypt_plain(plain=plain, key_id=key_id, client=kms_client)
        print(cipher)
        return
    elif decrypt:
        plain = decrypt_cipher(cipher=cipher, key_id=key_id, client=kms_client)
        print(plain)
        return

    logger.error(f"Not the expected result - nothing accomplished.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
