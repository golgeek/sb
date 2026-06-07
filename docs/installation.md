# Installation

## Compatibility

To manage system users and groups, `sb` runs a few system (mostly `coreutils`) commands in the background.

Because `sb` runs as an unprivileged user to ensure security at the system level, sudoers files (`/etc/sudoers.d/*`) 
are generated for all `sb` groups to grant group members the permission to execute very specific commands.

This design ensures security, but also brings a drawback: the commands have to sit at a specific location.

We mapped the commands to the `Debian` and `Ubuntu` world, but compatibility with other distributions is usually a few 
packages and symbolic links away.

<details>
  <summary>Compatibility with Alpine Linux</summary>

As an example, the compatibility with `Alpine Linux` only requires two things:
- Install the `openssh` and `shadow` packages:
```console
root@sb-alpine:~# apk add openssh shadow
```
- Link `/bin/touch` to `/usr/bin/touch`:
```console
root@sb-alpine:~# ln -s /bin/touch /usr/bin/touch
```
</details>


## Prepare your system

Here is the list of expected system commands:
- `/bin/chmod`
- `/bin/chown`
- `/bin/mkdir`
- `/bin/mv`
- `/bin/rm`
- `/usr/bin/ssh-keygen`
- `/usr/bin/sudo`
- `/usr/bin/tee`
- `/usr/bin/touch`
- `/usr/sbin/addgroup`
- `/usr/sbin/adduser`
- `/usr/sbin/deluser`
- `/usr/sbin/groupmod`
- `/usr/sbin/usermod`

To enable TOTP on top of SSH key pairs as a second method of authentication, it is also recommended to install:
- `libpam-google-authenticator`

Note that `sb` is also compatible with [Mosh](https://github.com/mobile-shell/mosh) and will require 
to have `mosh-server` available in the path.


## Install the binary

To install `sb`, simply drop the binary in `/opt/sb/sb` and make it executable.


## Configure sb

Adapt the following default configuration to your needs and put it in `/etc/sb/sb.yml`:

```yaml
commands:
  ssh_command: ttyrec

general:
  binary_path: /opt/sb/sb
  sb_user: sb
  sb_user_home: /home/sb
  hostname: sb.YOUR_DOMAIN.com
  name: sb-host1
  location: "us"
  ssh_port: 22
  mosh_ports_range: 40000:49999
  env_vars_to_forward: ["USER"]
  encryption-key: changemechangemechangemechangeme

replication:
  enabled: false
  queue:
    type: googlepubsub
    googlepubsub:
      project: demo-gcp-project
      topic: sb

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


## Trigger the setup command

The setup command will configure a few config files on the system.

Notably,
- in `/etc/ssh/sshd_config`:
  - [x] make sure that `PasswordAuthentication` is set to `no`
  - [x] make sure that `ChallengeResponseAuthentication` is set to `yes` (to enable TOTP)
  - [x] make sure that `PermitRootLogin` is set to `prohibit-password` (key/cert-based root maintenance still works; interactive root password logins are refused)
  - [x] make sure that `AuthenticationMethods` is set to `publickey,keyboard-interactive`

The setup also validates the resulting configuration with `sshd -t` before
restarting the SSH service. If the configuration is invalid, the original file is
restored and the service is not restarted, so a mistake cannot lock you out of
the host.
- configure `/etc/pam.d/sshd` to enable TOTP via `pam_google_authenticator` if it is installed on the system
- create the technical `sb` user
- create the `sudoers.d` file for sb `owners` group so that owners can create groups and users
- create the systemd service file for the daemonized binary

```console
root@sb-host1:~# /opt/sb/sb setup --user t800 --public-key "'PASTE YOUR PUBLIC SSH KEY HERE'"
```


## Setup the daemon

If you intend to use replication between multiple instances and/or TTYRecs offloading, 
you will also need to start `sb`'s daemon.

To enable the daemon, a systemd service file was created during the setup command, and you just need to start it:

```console
root@sb-host1:~# systemctl daemon-reload
root@sb-host1:~# systemctl enable sb.service
root@sb-host1:~# systemctl start sb.service
```

## Setup your first account

Once this is done, you can setup your own user by following [this documentation](./setup-first-account.md) 
with the help of the first user that was created during this setup.
