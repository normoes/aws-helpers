#!/usr/bin/env python

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

REGION_ = os.environ.get("AWS_REGION", None)
REGION = os.environ.get("AWS_DEFAULT_REGION", REGION_)
if not REGION:
    REGION = REGION_DEFAULT

# List keys.
IGNORED_ALIASES = ["alias/aws/"]  # Ignored KMS key aliases


def get_kms_keys(exclude_aws_alias=False, client=None):
    logger.info(f"Getting all the keys.")

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
                logger.error(
                    f"An alias for key '{key_id}' was not found: {str(e)}."
                )
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

    config.add_argument("-r", "--region", default=REGION, help="AWS region.")
    config.add_argument(
        "--debug", action="store_true", help="Show debug info."
    )

    subparsers = parser.add_subparsers(
        help="sub-command help", dest="subcommand"
    )
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
        "--key-id",
        default="",
        required=True,
        help="KMD key id to use for encryption.",
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
        "--key-id",
        default="",
        required=True,
        help="KMD key id to use for decryption.",
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
        keys = get_kms_keys(
            exclude_aws_alias=exclude_aws_alias, client=kms_client
        )
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
