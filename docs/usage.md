# Usage

Every access to your infrastructure should always be done via `sb` so that the session is logged and recorded.
The goal is not to spy on actual users, btw there are currently no admin command to easily grab the session recordings, 
but it gives a fighting chance to know what potential non-authorized people might have done if they ever enter in your 
infra!

Once you're connected to a machine in the infrastructure, feel free to jump to another host if you want. 
The session is still secured and recorded since your first connection was made via `sb`.

And if you're not sure what you did last time? That's OK! Just play your previous recording :)

## Basic usage

```console
t1000@skynet:~# alias sb
sb='ssh t1000@sb.domain.tld -A -t -- '
```

Get information about the `sb instance` and your account:

```console
t1000@skynet:~# sb info
Hi, t1000!

Here are a few information about the wonderful place you just connected to:
  -> my name is sb
  -> I'm located in Europe, my address is sb.domain.tld
  -> here is the list of my IP addresses: 127.0.0.1, 10.0.0.1
  -> I currently have 256 guests accounts
  -> I'm currently hosting 42 groups

If you want to interact with me, just one of these aliases:
  -> SSH:  alias sb='ssh t1000@sb.domain.tld -t -A --'
  -> MOSH: alias msb='mosh t1000@sb.domain.tld -A --'

But let's talk a bit about yourself, t1000!
  -> you're a member of 7 groups
  -> as you're a member of the owners group, you have extra admin privileges
  -> TOTP is enabled on your account
  -> you only have 2 unused emergency codes left. You should generate new ones right away!
```

List your own ingress SSH keys:
```console
t1000@skynet:~# sb self ingress-keys list
Here is the list of your current ingress public SSH keys (you -> sb):
1: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDLIfKoC3pm3STHcdLoL0cY3B4AXht0wyL2reE7uDc+L t1000@skynet
```

Add a new ingress SSH key to access `sb`:
```console
t1000@skynet:~# sb self ingress-key add
Here is the list of your current ingress public SSH keys (you -> sb):
1: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDLIfKoC3pm3STHcdLoL0cY3B4AXht0wyL2reE7uDc+L ludovic@inpher.io
Please paste the public key you want to add: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGaBmYsKHIkjcBzuqzrNjdhi5TvVwMKqpZSTFi5bVeE5 t1000@resistance
Your key was successfully added.
Here is the list of your current ingress public SSH keys (you -> sb):
1: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDLIfKoC3pm3STHcdLoL0cY3B4AXht0wyL2reE7uDc+L t1000@skynet
---
2: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGaBmYsKHIkjcBzuqzrNjdhi5TvVwMKqpZSTFi5bVeE5 t1000@resistance
```

List your personal accesses:
```console
t1000@skynet:~# sb self accesses list
Here is the list of your accessible distant hosts:
Host: devengine.domain.tld           | User: user       | Port: 22
Host: compiler.domain.tld            | User: user       | Port: 22
Host: sb.domain.tld                  | User: root       | Port: 22
```

List the groups existing on the `sb` cluster:
```console
t1000@skynet:~# sb groups list
Here are the list of sb groups:
owners
robots
```

Get information on a group:
```console
t1000@skynet:~# sb group info --group robots
Here are the basic information for the group sysadmins:

List of group's owners (can do everything): t1000, jconnor
List of group's gate-keepers (can add members): t1000
List of group's acl-keepers (can add accesses):  t1000
List of group's members (can connect to devices):  t800, t888, t1000

List of group's egress public SSH keys (sb -> distant host):
1: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEPWmnO62I5fXO4ZS0CS1GlN5E38Bkm5pkYVI40g0yZ/ robots@sb.domain.tld
```

List the accesses granted by a group:
```console
t1000@skynet:~# sb group accesses list --group robots   
Here is the list of the group's accessible distant hosts:
Host: core.skynet.org            | User: root       | Port: 22
```

Display the exhaustive list of commands:
```console
t1000@skynet:~# sb help
Usage: sb [OPTION | HOST | COMMAND]

Available options:
  -i: launch sb in interactive mode

Host supported formats:
  - full formats:
    - user@example.com:22
    - user@127.0.0.1:22
  - short formats*:
    - user@example.com : port will be retrieved from granted access
    - example.com:22   : user will be retrieved from granted access
    - example.com      : port and user will be retrieved from granted access
  - alias*:
    - user@alias:port  : host will be retrieved from granted access
    - user@alias       : host and port will be retrieved from granted access
    - alias:port       : host and user will be retrieved from granted access
    - alias            : host, user and port will be retrieved from granted access
* If multiple granted access match a short format or an alias,
user will be interactively prompted to choose the desired access

Available commands:
  - account create                     : create a new account on sb
  - account delete                     : delete an account from sb
  - group access add                   : add a group access to a distant host
  - group access remove                : remove a group access to a distant host
  - group accesses list                : list the hosts accessible to a group
  - group acl-keeper add               : add an account as a group ACL keeper
  - group acl-keeper remove            : remove an account from the ACL keepers of a group
  - group create                       : create a new group on sb
  - group delete                       : delete a group from sb
  - group egress-key generate          : generate a new SSH egress (sb -> distant host) key for a group
  - group gate-keeper add              : add an account as a group gate keeper
  - group gate-keeper remove           : remove an account from the gate keepers of a group
  - group info                         : display the basic information of a group
  - group member add                   : add an account as a group member
  - group member remove                : remove an account from the members of a group
  - group owner add                    : add an account as a group owner
  - group owner remove                 : remove an account from the owners of a group
  - groups list                        : display the list of groups
  - help                               : display this help
  - info                               : display info on sb and your account
  - scp                                : transfer a file from or to a distant host through sb
  - self access add                    : add a personal access to a distant host
  - self access remove                 : remove a personal access to a distant host
  - self accesses list                 : list the hosts accessible to this account
  - self egress-key generate           : generate a new SSH egress (sb -> distant host) key for your account
  - self egress-keys list              : lists your egress public keys (sb -> distant host)
  - self hostkey forget                : forget a hostkey
  - self ingress-key add               : add a new public ingress key (you -> sb) to your account
  - self ingress-key delete            : delete a public ingress key (you -> sb) from your account
  - self ingress-keys list             : list your ingress public keys (you -> sb)
  - self session gif                   : get a recording of an SSH session as a gif
  - self session replay                : watch a recording of an SSH session
  - self sessions list                 : list your last 20 SSH sessions
  - self totp disable                  : disable TOTP on the account
  - self totp emergency-codes generate : generate TOTP emergency codes
  - self totp enable                   : enable TOTP on the account
```

## Egress host-key verification

When `sb` connects you to a distant host (interactive sessions and SCP alike), it pins the
host-key check on that bastion → host hop instead of relying on inherited SSH defaults. Each
distant host key is recorded in your managed `known_hosts` on the bastion, and the policy is
controlled by `general.egress_strict_host_key_checking`
([configuration](./configuration.md#general)):

- `accept-new` (default): the first time a host is seen, its key is pinned automatically;
  if a pinned host later presents a **different** key, the connection is refused
  (trust-on-first-use with pinning). This protects the session — and the forwarded agent —
  from a host whose key has changed.
- `yes`: refuse any host that is not already pinned (use this if you provision host keys out
  of band).
- `no`: disable verification entirely (strongly discouraged).

If a connection is refused because a host key changed, `sb` prints a ready-to-paste command
that clears the stale pin via `self hostkey forget`. **Only run it if you trust the change**
(e.g. the host was legitimately rebuilt) — a key change can also be a man-in-the-middle
attack:

```console
t1000@skynet:~# ssh -p 22 t1000@sb.YOUR_DOMAIN.com "self hostkey forget --hostkey '10.0.0.10'"
```

Then reconnect; the new key is pinned on the next connection.

## Use SCP across sb

If your goal is to transfer files from or to a distant host with `scp` through `sb`, you're in luck!

First, you'll need to setup your local machine by downloading an `scp program` from `sb`:
```console
t1000@skynet:~# sb scp --get-script > ~/.sbscp && chmod +x ~/.sbscp
```

This command downloaded a program that was saved in the `.sbscp` file in your home directory, and was made executable.

Then, you'll need to set up yet another alias:
```console
t1000@skynet:~# alias sbscp='scp -S ~/.sbscp '
```

And that's pretty much it, just use `sbscp` as you would use `scp`!
```console
t1000@skynet:~# sbscp README.md root@10.0.0.10:/tmp/README.md
Authenticated to 10.0.0.1 ([10.0.0.1]:22).
README.md                     100% 3207   126.3KB/s   00:00    
Transferred: sent 5396, received 2812 bytes, in 1.0 seconds
Bytes per second: sent 5417.9, received 2823.4
```

## Enable and use Time-based One-Time Password

If you want an extra security on top of the SSH key pair authentication when connecting to `sb`, 
you can enable TOTP on your account. 

The following command will trigger the TOTP setup on `sb`:
```console
t1000@skynet:~# sb self totp enable
```

It will display an `otpauth URL`, a `secret key` and a `QR-Code` that you will need to configure 
in an application like `Google Authenticator`, `Authy` or any other TOTP application.

Once this is done, you just need to validate that you configured your TOTP application correctly 
by entering a validation code generated by the application. If the code is correct, you're all set!

`sb` will provide you with 5 emergency codes that you need to keep securely in case you lose access 
to your TOTP application. These codes will never been shown again, and each of these can replace a TOTP only once.

You can generate new codes with the following command:
```console
t1000@skynet:~# sb self totp emergency-codes generate
```

You can also disable TOTP on your account with the following command:
```console
t1000@skynet:~# sb self totp disable
```