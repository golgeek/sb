<p align="center">
<img alt="SB logo" src="./docs/assets/logo.png"><br>
<h1 align="center">S(sh) B(astion)</h1>
<p align="center">
  <img alt="Test status" src="https://github.com/golgeek/sb/actions/workflows/tests.yml/badge.svg?branch=main&event=push">
  <a href="http://goreportcard.com/report/golgeek/sb">
     <img alt="Go report" src="https://img.shields.io/badge/Go_report-A+-brightgreen.svg">
  </a>
  <a href="https://opensource.org/licenses/MIT">
    <img alt="License" src="https://img.shields.io/badge/license-MIT-brightgreen.svg">
  </a>
  <a href="https://github.com/golgeek/sb/releases/latest">
    <img alt="Release" src="https://img.shields.io/github/release/golgeek/sb.svg">
  </a>
</p>

## Intro

As a junior DevOps, you probably learned that you don't mess with security, and that publicly exposing a host 
(server, vm, cloud instance, ...) to the internet is messing with security.

But you (and your teams) still need to access these distant hosts, and setting firewall rules for every employee 
of your company is just not manageable.

This is usually where SSH ProxyJump comes in play: having a central point from where you will connect 
to your infrastructure. You can firewall every distant host to the IP address of your jump host, and all you have to do 
is to ensure that this central point is secured!

This is cool, but now that you still have two main issues:
- you need to provision every employee's SSH keys to every distant host
- you need to revoke these keys on every distant host when the employee leaves
- you just added a single point of failure in your infrastructure


## `sb` enters the place

In a nutshell, `sb` fixes these three issues and then more!

As an SSH bastion, it works by piping two SSH connections together (employee -> sb -> distant host).

Since you now have two separate SSH connections, the user is authenticated on the bastion by the bastion, 
and this is where (and only where) their public SSH key sits... revoking just became easy!

_But that's not it!_

Without compromising the security, `sb` brings groups with shared SSH keys that stay on the bastion. 
You don't have to provision keys anymore, and you just have to grant access to distant hosts to your users.

_But that's not it!_

`sb` supports multi-primary replication between instances: you create users on one instance, 
they can use another geo-replicated instance in seconds!


## Cherry on the cake

On top of security and high-availability, `sb` brings auditability and traceability for free to your infrastructure!

By only granting accesses to users and groups through `sb`, you can easily know who can (and did) access what 
at all time. This is, for example, required for ISO 27001.

Plus for higher norms (_SOC1_, _SOC2_, _PCI-DSS_, ...), every SSH session is recorded via TTYRec, so you can replay it!

And because you have the session recording, why not allow the users to replay their sessions with TTYPlay 
or even convert these recordings as GIF?

![recording.gif](./docs/assets/recording.gif)

# Documentation

Quick demo with Docker images:
1. [Demo](./docs/demo.md)

General and features documentation:
1. [Genesis and core ideology](./docs/genesis-core-ideology.md)
2. [Permissions](./docs/permissions.md)
3. [High Availability](./docs/high-availability.md)
4. [Usage examples](./docs/usage.md)
5. [Features](./docs/features.md)

Administration documentation:
1. [Installation](./docs/installation.md)
2. [Setup first account](./docs/setup-first-account.md)
3. [Configuration](./docs/configuration.md)
4. [Backup and restore](./docs/backup-and-restore.md)
5. [Production deployment](./docs/production-deployment.md)

# License

Released under the [MIT License](https://github.com/golgeek/sb/blob/master/LICENSE)
