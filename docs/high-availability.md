# High availability

A key feature of `sb` is that it has been designed with multiple primary instances in mind.


## Replication

When you execute a command on any `sb` instance in a cluster (let's say create a new user),
the action will be replicated to the other instance(s).


### How does it work?

Whenever [replication is enabled in the configuration](./configuration.md#replication), every action executed in `sb`
will result in:
1. the action being executed locally as usual
2. all data used for this action being encrypted and inserted in a local replication SQLite database

Note that enabling the replication also means [starting the associated daemon](./installation.md#setup-the-daemon).

> **Important:** the encrypted replication payloads carry secrets (including TOTP secrets and
> recovery codes), so the daemon **refuses to start** if replication (or TTYRecs offloading)
> is enabled while [`general.encryption-key`](./configuration.md#general) is left empty or at
> the shipped placeholder. Set a real, unique key — **shared across all instances** so they
> can decrypt each other's payloads — before enabling replication.

This daemon executes three processes:
1. query the replication database and push the entries to a message queue
2. listen to the message queue and perform the replication actions for each entry it receives
3. execute the PostExecution steps of the commands (mainly used for TTYRecs offloading)


### Supported Message Queues

As of today, only [Google PubSub](https://cloud.google.com/pubsub) is supported, but another message queue
can be added very fast by implementing [the replicationqueue interface](../internal/replicationqueue/replicationQueue.go).



## TTYRecs offloading

Every action being synced between all instances, it is expected that you can start a session on one `sb` instance,
and replay it on another instance a few moments later.


### How does it work?

When [the feature is enabled](./configuration.md#ttyrecs-offloading), the TTYRecs will be offloaded
by [the daemon](./installation.md#setup-the-daemon) to a remote object storage once an SSH session has ended.

Note that enabling the replication also means [starting the associated daemon](./installation.md#setup-the-daemon).

All TTYRecs are kept on disk while the SSH session is running.

When the session ends:
1. The replication entry is added to the replication database
2. The daemon pulls it and triggers the post-execution step:
  1. the TTYRec file is encrypted with the replication encryption-key
  2. the TTYRec file is pushed to a distant object storage
  3. the local TTYRec file is removed from the disk


### Supported object storage

As of today, the two following object storage solutions are supported:
- [Google Cloud Storage](https://cloud.google.com/storage)
- [Amazon S3](https://aws.amazon.com/s3/)

Other remote storage systems can be added very fast by implementing
the [storage interface](../internal/storage/storage.go).
