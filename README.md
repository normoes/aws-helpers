# aws-helpers

## ecs_aws_services

This pypi package has moved to https://pypi.org/project/aws-ecs-services/.

## cloudwatch_logs

This pypi package has moved to https://pypi.org/project/aws-cloudwatch-logs/.

## kms

`aws_kms_keys.py`

The default region is `eu-west-1`, change with the `--region` flag.

This tool interacts with AWS KMS keys in the following ways:
* Lists all keys `python aws_kms_keys.py list-keys`:
    * Including `alias/aws/` aliased keys by default.
    * Excluding `alias/aws/` aliased keys with the `--exclude-aws-alias` flag.
* Encrypts a plain text with a given AWS KMS key:
    ```
        python aws_kms_keys.py encrypt --region <aws_region>  --plain="<text_to_encrypt>" --key-id=<key_id>
    ```
* Decrypts a previously encrypted plain text with a given AWS KMS key:
    ```
        python aws_kms_keys.py decrypt --region <aws_region>  --cipher="<previously_encrypted_plain_text>" --key-id=<key_id>
    ```

## list_chamber_services

`aws-ssm-pstore`

### Why

This tool is deprecated since `chamber` now provides:
```
    chamber list-services
```
which does exactly what this tool aimed at.

---

Using **chamber** (https://github.com/segmentio/chamber) to manage the AWS Paremter Store (part of SSM - AWS Systems Manager), I was missing the possiblitiy to list chamber services which are basically just the first part of the parameter name.

With a parameter called `/project/database_url` that has the value `postgres://user:passwd@some_endpoint.com:5432`, the service (in **chamber** talk) is `/project/`.

~~**chamber** itself does not offer such an option.~~

There is a ~~pending~~ merged [PR](https://github.com/segmentio/chamber/pull/187) which implements this feature.

### How

`aws-ssm-pstore` is using `aws-vault` internally. So naturally `aws-vault` needs to be installed as well.

Also, to get the parameters, `jq` is usedand should be installed.

`aws-ssm-pstore` supports one password backend, that is [`pass`](https://www.passwordstore.org/). In fact, the password backend is a configuration for `aws-vault`.

### Usage

You can use `aws-ssm-pstore` with a profile name defined within your `~/.aws/config` file.
```
aws-ssm-pstore <profile_from_~/.aws/config>
```

You can use `pass` as password backend (for `aws-vault`) with `aws-ssm-pstore`. In this case you need to provide the path to the specific password store.
```
aws-ssm-pstore <profile_from_~/.aws/config> <path_to_path_keystore_folder>

# example
aws-ssm-pstore some_aws_profile ~/.password-store/aws/vaults
# with ./aws/config similar to this (not complete)
[profile some_aws_profile]
aws_account_id = xxx
role_arn=arn:aws:iam::xxx:role/some_role
source_profile=source_profile
color = d67d7d
```

### bash completetion

It's possible to install bash completion for this script.

Just copy `aws-ssm-pstore` to a directory that is contained in your `PATH` variable.
```
# example
cp aws-ssm-pstore ~/.local/bin/
```
Copy the bash compeletion script.
```
cp aws-ssm-pstore-completion.bash /etc/bash_completion.d/
```

Use it like this:
```
# <TAB> indicates pressing the TAB key
aws-ssm-pstore some_<TAB> ~/.password-store/<TAB>
```

### AWS and chamber configuration

Change the appropriate environment variables to get secrets from another AWS region (other than the default AWS region which might be `eu-west-1`):
```
 AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1 aws-ssm-pstore <profile_from_~/.aws/config> <path_to_path_keystore_folder>
```

Change the appropriate environment variables to write secrets with another AWS KMS key (other than the default **chamber** key `parameter_store_key`):
```
CHAMBER_KMS_KEY_ALIAS=not_default_key aws-ssm-pstore <profile_from_~/.aws/config> <path_to_path_keystore_folder>
```
