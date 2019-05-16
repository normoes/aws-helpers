# aws-helpers

## aws-ssm-pstore

### Why
Using **chamber** (https://github.com/segmentio/chamber) to manage the AWS Paremter Store (part of SSM - AWS Systems Manager), I was missing the possiblitiy to list chamber services which are basically just the first part of the parameter name.

With a parameter called `/project/database_url` that has the value `postgres://user:passwd@some_endpoint.com:5432`, the service (in **chamber** talk) is `project`.

**chamber** itself does not offer such an option.

### How

`aws-ssm-pstore` is using `aws-vault` internally. So naturally `aws-vault` needs to be installed as well.

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
# with ./aws/config similar to this (not compelte)
[profile some_aws_profile]
aws_account_id = xxx
role_arn=arn:aws:iam::xxx:role/some_role
source_profile=source_profile
color = d67d7d
```

## bash completetion

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

## AWS and chamber configuration

Change the appropriate environment variables to get secrets from another AWS region (other than the default AWS region which might be `eu-west-1`):
```
 AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1 aws-ssm-pstore <profile_from_~/.aws/config> <path_to_path_keystore_folder>
```

Change the appropriate environment variables to write secrets with another AWS KMS key (other than the default **chamber** key `parameter_store_key`):
```
CHAMBER_KMS_KEY_ALIAS=not_default_key aws-ssm-pstore <profile_from_~/.aws/config> <path_to_path_keystore_folder>
```
