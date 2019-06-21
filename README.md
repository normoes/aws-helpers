# aws-helpers

## aws_get_instance_service_runs_on.py

### Why
I would like to easily ssh into the instance an ECS service is running on. When deployed into a cluster with several instances you cannot accomplish this using `awscli`.

I work through a VPN, so I am only interested in the instances' private IP addresses. When using the AWS Session Manager I am interested in the instance's id.

I found a way for **ECS services that use service discovery** and register a DNS name with AWS Route53.

If the infrastructure is deployed with terraform, the service names as well as the DNS names of the services become predictable.

### How

The tool is best used with `aws-vault`. So far I did not implement reading AWS profiles with `boto3` e.g.

The tool gets the DNS name of the service (AWS Route53). It also gets the name of the cluster the service was created in. Also the tool gets the AWS region to use.

The association between the service's DNS name and the instance provate IP.
* Get the IP of the service by the DNS name (host name).
  - IP is changing constantly (with every deployment), DNS name is not.
* Get all the cluster instances.
  - Make sure you configure the correct cluster (service nneds to be located in there).
* Get the private IP addresses of these instances and compareto the IP address of the service.
* The match reveals the correct instance.

There are more elegant ways for sure. This one is working and might get optimized over time.

### Usage

I created an alias to directly use the output of the tool and ssh into the appropriate EC2 instance:
```
ssh ec2-user@"$(aws-vault-alias-using-password-manager -- /path/to/aws_get_instance_service_runs_on.py --region eu-west-2 --cluster my-cluster --dns dns.name.com)"
```

The default output is the instance's private IP address.

If called with `--output id` it displays the instance's id.

If called with `--output all` it displays both of the values above. In addition it returns the instance's private DNS name.

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
