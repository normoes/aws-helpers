# Cloudwatch logs

Get logs from AWS CloudWatch.

A wokring AWS configuration is expcted.

I personally use `aws-vault` for that matter.

## Why

There are tools  like `saw`, but I am not quite comfortable with all of them. So I just wanted to try and do it myself.

## Usage

Get help:
```
    aws_get_logs -h
    aws_get_logs get-stream -h
    aws_get_logs follow-stream -h
    aws_get_logs insights -h
```

### Get the most recent log events of a stream
```
    # Get log events going 1 hour back in time, until now.
    aws_get_logs.py get-stream --region <aws_region> --group <log_group> --stream <log_stream_prefix>  --start-time 1
    # Get log events going 1 minute back in time, until now.
    aws_get_logs.py get-stream --group <log_group> --stream <log_stream_prefix>  --start-time 1 --time_unit minutes
```

This returns the most recent log events of the given stream.

The `--limit` option actually affects the total number if log events returned.

### Follow the most recent log events of a stream
```
    # Get log events going 1 hour back in time, follow the log stream and listen for more.
    aws_get_logs follow-stream --region <aws_region> --group <log_group> --stream <log_stream_prefix>  --start-time 1
```

This is mostly the same as  the above. It returns the most recent logevents of the given stream, but stays "connected" and gives every new incoming log event as well.
The loop is broken e.g. by a `KeyboardInterrupt`.

The `--limit` option reduces the number of log events retrieved by a single request.
Requests will be repeated (the stream is followed) until the program stops.

### Using Insights
```
    aws_get_logs insights --region <aws_region> --group <log_group> --start_time 1 --limit 1000 --query 'fields @timestamp, @message | sort @timestamp desc | limit 20'
```

This command allows querying AWS CloudWatch logs using Insights.

## Configuration

### Ways to configure
When used as an executable or script the configuration happens using cli arguments.

The tool also considers environment variables.

This is the mapping:

| cli option | environemt variable | default |
|------------|---------------------|---------|
| `-r`, `--region` |` AWS_REGION` | eu-west-1 |
| `-g`, `--group` | `LOG_GROUP` | `None` |
| `-s`, `--stream` | `LOG_STREAM` | `None` |
| `--start_time` | `START_TIME` | `3` |
| `--time_unit` | `TIME_UNIT` | hours |
| `--limit` | `LIMIT` | `20` |
| `--query` | `QUERY` | fields @timestamp, @message &#124; sort @timestamp desc &#124; limit 20 |

### Options
The `--start_time` expects an integer. Additionally the option `--time_unit`, which defaults to `hours`, can be used.

`--start_time` defaults to `3`.

Possible values for `--time_unit` are:
* `hours` (**default**)
* `minutes`

Also, there is a `--limit` option which limits the result per request.

`--limit` defaults to `20`.

The given log stream name is evaluated using the option `logStreamNamePrefix` of the `filter_log_events` function of the **boto3** logs client.
I.e. it's not important to specifiy the complete and exact log stream name, but an **exact prefix**.
