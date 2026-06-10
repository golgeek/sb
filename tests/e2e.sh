#!/usr/bin/env bash

set -e
shopt -s expand_aliases

# Start ssh-agent to handle the demo private-key
ssh-agent > /tmp/ssh-agent.sh
source /tmp/ssh-agent.sh

# Fix permissions for demo SSH key
chmod 600 $(pwd)/demo/assets/ssh-keys/id_ed25519

# Add the demo private-key
ssh-add $(pwd)/demo/assets/ssh-keys/id_ed25519

# Setup all aliases
alias sb1="ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -p 22001 t800@127.0.0.1 -A -tt -- "
alias sb2="ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -p 22002 t800@127.0.0.1 -A -tt -- "
alias sbscp="scp -O -S /tmp/.sbdemoscp "

echo "Generate an egress key"

sb1 self egress-key generate --algo ed25519 --size 256

echo "Get the generated public key"

export TRUSTED_KEY=$(sb1 self egress-keys list | sed -e 's/\x1b\[[0-9;]*m//g' | grep -e "^1:" | sed -e 's/^1: //')

echo "Push the key ${TRUSTED_KEY} to the docker examplevm container"

docker exec sbdemo_examplevm /bin/bash -c "echo '$TRUSTED_KEY' > /root/.ssh/authorized_keys"

echo "Grant personal access to examplevm"

sb1 self access add --host examplevm --port 22 --user root

# Wait for replication to be OK
sleep 5

echo "Execute a command on examplevm"

if ! sb2 root@examplevm -- echo "test"; then
   echo "Unable to connect to examplevm via sb2";
   exit 1;
fi

echo "Check that the session was recorded"

if ! sb2 self sessions list | grep -q "Session ID"; then
    echo "Session was not saved in logs on sb2";
    exit 1;
fi

# Wait for replication to be OK
sleep 5

echo "Check that the session was replicated"

if ! sb1 self sessions list | grep -q "Session ID"; then
    echo "Session was not replicated in logs on sb1";
    exit 1;
fi

echo "Check that we cannot connect to an unauthorized host"

if ! sb2 test@examplevm -- echo "test" | grep -q "user can't access the host"; then
    echo "User shouldn't be able to access examplevm as user test";
    exit 1;
fi

echo "Get the SCP program"

if ! sb1 scp --get-script > /tmp/.sbdemoscp; then
    echo "Unable to get the SCP program";
    exit 1;
fi

chmod +x /tmp/.sbdemoscp

# Adapt the script to our unsecured test environment
sed -i 's/ssh /ssh -o UserKnownHostsFile=\/dev\/null -o StrictHostKeyChecking=no /' /tmp/.sbdemoscp

echo "SCP recursively to the VM"

if ! sbscp -r ./docs root@examplevm:/root; then
    echo "Unable to SCP recursively to examplevm";
    exit 1;
fi

echo "Check that the content was indeed copied over to examplevm"

if ! sb1 root@examplevm -- cat docs/demo.md | grep -q "# Demo"; then
    echo "Unable to check if the content was copied over to examplevm"
    exit 1
fi

# ---------------------------------------------------------------------------
# Permission checks
#
# t800 (created at image build time) owns the "owners" super-group, so every
# check above runs with full privileges. The checks below create a second,
# unprivileged account (t1000) and assert that each rights level actually
# refuses it, then that an explicit role grant lifts exactly the matching
# refusal. Every probe passes all required arguments so it reaches the
# authorization check instead of failing earlier on argument validation.
# ---------------------------------------------------------------------------

echo "Create an unprivileged account t1000 (as the sb owner t800)"

# The key is wrapped in literal single quotes: ssh flattens its arguments into
# one remote command string, and the quotes keep the multi-word key a single
# argument for the bastion's own command-line parser.
if ! sb1 account create --username t1000 --public-key "'$(cat "$(pwd)/demo/assets/ssh-keys/id_ed25519.pub")'"; then
    echo "Unable to create the unprivileged account t1000";
    exit 1;
fi

# t1000 uses the same demo key pair as t800, only the account differs
alias sb1u="ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -p 22001 t1000@127.0.0.1 -A -tt -- "

echo "Check that a non-owner cannot create accounts (SBOwner level)"

if ! sb1u account create --username eve --public-key "irrelevant" | grep -q "user is not a sb owner"; then
    echo "t1000 should not be able to create accounts";
    exit 1;
fi

echo "Check that a non-owner cannot create groups (SBOwner level)"

if ! sb1u group create --name evilcorp --owner-account t1000 --algo ed25519 --size 256 | grep -q "user is not a sb owner"; then
    echo "t1000 should not be able to create groups";
    exit 1;
fi

echo "Check that even the sb owner cannot run root-only commands (Private level)"

if ! sb1 backup --backup-directory /tmp | grep -q "only root user can execute this command"; then
    echo "t800 should not be able to run the root-only backup command";
    exit 1;
fi

echo "Create the group redteam owned by t800 (group-level checks fixture)"

if ! sb1 group create --name redteam --owner-account t800 --algo ed25519 --size 256; then
    echo "Unable to create the redteam group";
    exit 1;
fi

echo "Check that the ACL keeper can grant the group an access (GroupACLKeeper level)"

# t800 holds every role on redteam (group creation grants the owner account
# all of them). Granting an access here also writes the group's accesses
# database schema: the file starts empty, and the first write must come from
# an ACL keeper — a plain member only has read permission on it.
if ! sb1 group access add --group redteam --host examplevm --user root --port 22; then
    echo "t800, an ACL keeper of redteam, should be able to grant it an access";
    exit 1;
fi

echo "Check that a non-member cannot list the group's accesses (GroupMember level)"

if ! sb1u group accesses list --group redteam | grep -q "user is not a member of the group"; then
    echo "t1000 should not be able to list redteam's accesses";
    exit 1;
fi

echo "Check that a non-gate-keeper cannot add members (GroupGateKeeper level)"

if ! sb1u group member add --group redteam --account t1000 | grep -q "user is not a gate keeper of the group"; then
    echo "t1000 should not be able to add itself as a redteam member";
    exit 1;
fi

echo "Check that a non-ACL-keeper cannot grant accesses (GroupACLKeeper level)"

if ! sb1u group access add --group redteam --host examplevm --user root --port 22 | grep -q "user is not an ACL keeper of the group"; then
    echo "t1000 should not be able to grant accesses to redteam";
    exit 1;
fi

echo "Check that a non-owner cannot add owners (GroupOwner level)"

if ! sb1u group owner add --group redteam --account t1000 | grep -q "user is not an owner of the group"; then
    echo "t1000 should not be able to make itself a redteam owner";
    exit 1;
fi

echo "Grant t1000 the gate-keeper role on redteam (as the group owner t800)"

if ! sb1 group gate-keeper add --group redteam --account t1000; then
    echo "t800 should be able to add t1000 as a redteam gate keeper";
    exit 1;
fi

echo "Check that the gate keeper can now add members (GroupGateKeeper level)"

if ! sb1u group member add --group redteam --account t1000; then
    echo "t1000, now a gate keeper, should be able to add itself as a redteam member";
    exit 1;
fi

echo "Check that the member can now list the group's accesses (GroupMember level)"

if ! sb1u group accesses list --group redteam | grep -q "examplevm"; then
    echo "t1000, now a member, should be able to list redteam's accesses";
    exit 1;
fi

echo "Check that the gate keeper still cannot grant accesses (roles are independent)"

if ! sb1u group access add --group redteam --host examplevm --user root --port 22 | grep -q "user is not an ACL keeper of the group"; then
    echo "t1000's gate-keeper role should not grant ACL-keeper rights";
    exit 1;
fi

exit 0;