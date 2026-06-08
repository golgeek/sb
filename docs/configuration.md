# Configuration

This describes `sb`'s main configuration options.

## Commands

This block only describes the command (as in [cmd/*.go](../cmd/)) that is executed when connecting to a host.

```yaml
commands:
  ssh_command: ttyrec
```

Right now, the only valid option is `ttyrec`: it will connect you to the distant host via `ssh` while recording 
the session with `ttyrec`.

## General

```yaml
general:
  binary_path: /opt/sb/sb
  sb_user: sb
  sb_user_home: /home/sb
  hostname: sb.YOUR_DOMAIN.com
  name: sb-us
  location: "us"
  ssh_port: 22
  mosh_ports_range: 40000:49999
  env_vars_to_forward: ["USER"]
  encryption-key: changemechangemechangemechangeme
```

- `binary_path` (string): the path where `sb`'s binary is on the bastion server
- `sb_user` (string): the main `sb` system user
- `sb_user_home` (string): the home of the main `sb` user (where global logs are stored)
- `hostname` (string): the hostname of this instance; it will be displayed in the information
- `name` (string): the name of this instance; it will be displayed in the information
- `location` (string): the location of this instance; it will be displayed in the information
- `ssh_port` (int): the port SSH listens on for this instance
- `mosh_port_range` (string): the UDP range ports that [Mosh](https://github.com/mobile-shell/mosh) can use
- `env_vars_to_forward` ([]string): the environment variables that `sb` will forward to a distant host
- `encryption-key` (string): the encryption key for replication, TTYRecs offloading and backups; 
  it must be either 16, 24 or 32 characters.

  > **Important:** this key protects secrets that leave the host — replication payloads
  > carry TOTP secrets and recovery codes, and offloaded session recordings can contain
  > sensitive output. If you enable **replication** or **TTYRecs offloading** while this key
  > is left empty or at the shipped placeholder (`changemechangemechangemechangeme`), the
  > replication/offloading daemon (`sb -d`) **refuses to start** and tells you to set a real
  > key. The interactive login path is unaffected, so users are never locked out of the
  > bastion. Replicated instances must share the **same** key so they can decrypt each
  > other's payloads. To rotate it, set the new value on every instance and restart the
  > daemon on each; in-flight payloads encrypted with the old key must be drained (or
  > discarded) before the old key is removed.

## Replication

To learn about replication and high availability, please refer 
to [the dedicated documentation](./high-availability.md).

```yaml
replication:
  enabled: false
  queue:
    type: googlepubsub
    googlepubsub:
      project: demo-gcp-project
      topic: sb
```

- `enabled` (bool): whether or not replication is enabled
- `queue`:
  - `type` (string): the type of queue to use; as of today, only `googlepubsub`
  - `googlepubsub`:
    - `project` (string): The GCP project that hosts the Google PubSub queue
    - `topic` (string): The queue's topic

To avoid multiple instances pulling from the same Google PubSub subscription, each `sb` instance registers 
to a `subscription` built on the following model: `[topic-name]-[linux-hostname]`.

If the subscription doesn't exist, it is set to be created automatically.

## TTYRecs offloading

To learn about TTYRecs offloading and high availability, please refer 
to [the dedicated documentation](./high-availability.md#ttyrecs-offloading).

```yaml
ttyrecsoffloading:
  enabled: false
  storage:
    type: gcs
    gcs:
      bucket: sb-bucket
      objects-base-path: ttyrecs
    s3:
      region: us-east-2
      bucket: sb-bucket
      keys-base-path: ttyrecs
      aws-access-key: xxx
      aws-secret-key: xxx
      aws-session-token: xxx
```

- `enabled` (bool): whether or not TTYRecs offloading is enabled
- `storage`:
  - `type` (string): the type of remote storage to use; as of today only `gcs` or `s3`
  - `gcs`:
    - `bucket` (string): the Google Cloud Storage bucket to use
    - `objects-base-path` (string): the objects' prefix in the bucket
  - `s3`:
    - `region` (string): the region the Amazon S3 bucket sits
    - `bucket` (string): the Amazon S3 bucket to use
    - `keys-base-path` (string): the objects' prefix in the bucket
    - `aws-access-key` (string): optional AWS access key; if not specified, taken from the environment
    - `aws-secret-key` (string): optional AWS secret key; if not specified, taken from the environment
    - `aws-session-token` (string): optional AWS session token to use; if not specified, taken from the environment
