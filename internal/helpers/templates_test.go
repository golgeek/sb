package helpers

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetGroupSudoersTemplate(t *testing.T) {
	expectedSudoers := `# Owners' rights
%test-o		ALL=(root)		NOPASSWD: /usr/sbin/usermod -a -G test * 		# add a user as group's members
%test-o		ALL=(root)		NOPASSWD: /usr/sbin/usermod -a -G test-o * 		# add a user as group's owners
%test-o		ALL=(root)		NOPASSWD: /usr/sbin/usermod -a -G test-gk * 		# add a user as group's gate-keepers
%test-o		ALL=(root)		NOPASSWD: /usr/sbin/usermod -a -G test-aclk *		# add a user as group's acl-keepers
%test-o		ALL=(root)		NOPASSWD: /usr/sbin/deluser * test			# remove a user from the group's members
%test-o		ALL=(root)		NOPASSWD: /usr/sbin/deluser * test-o			# remove a user from the group's owners
%test-o		ALL=(root)		NOPASSWD: /usr/sbin/deluser * test-gk			# remove a user from the group's gate-keerps
%test-o		ALL=(root)		NOPASSWD: /usr/sbin/deluser * test-aclk			# remove a user from the group's acl-keepers
%test-o		ALL=(test)		NOPASSWD: /usr/bin/tee /home/test/.ssh/*			# create the private keypairs
%test-o		ALL=(test)		NOPASSWD: /bin/chmod 0600 /home/test/.ssh/*              # set the key private key as group readable
%test-o		ALL=(test)		NOPASSWD: /bin/chmod 0440 /home/test/.ssh/*              # set the key private key as group readable
%test-o		ALL=(test)		NOPASSWD: /bin/chmod 0644 /home/test/.ssh/*.pub              # set the key private key as group readable

# Gate keepers' rights
%test-gk	ALL=(root)		NOPASSWD: /usr/sbin/usermod -a -G test * 		# add a user as group's members
%test-gk	ALL=(root)		NOPASSWD: /usr/sbin/deluser * test			# remove a user from the group's members

# ACL keepers' rights
# No sudo commands here`

	require.Equal(t, expectedSudoers, getGroupSudoersTemplate("test"), "The GetScpScript() function returned an unexpected SCP script")
}

func TestGetScpScript(t *testing.T) {

	expectedScript := `#! /bin/sh
sftp=0
while ! [ "$1" = "--" ] ; do
	if [ "$1" = "-l" ] ; then
		user="$2"
		shift 2
	elif [ "$1" = "-p" ] ; then
		port="$2"
		shift 2
	elif [ "$1" = "-s" ] ; then
		sftp=1
		shift
	else
		sshcmdline="$sshcmdline $1"
		shift
	fi
done
host="$2"
if [ "x$user" != "x" ]; then
	host="$user@$host"
fi
if [ "x$port" != "x" ]; then
	host="$host:$port"
fi
if [ "$sftp" = "1" ] ; then
	exec ssh -p 22 test@sb.domain.tld $sshcmdline -T -- scp --access $host --scp-cmd sftp
else
	exec ssh -p 22 test@sb.domain.tld $sshcmdline -T -- scp --access $host --scp-cmd "\"$3\""
fi
`

	require.Equal(t, expectedScript, GetScpScript("test", "sb.domain.tld", "22"), "The GetScpScript() function returned an unexpected SCP script")

	// Guard against the historical regression where the -p test was emitted as
	// the literal "\$1" (text/template does not interpret \$), which broke port
	// handling. The corrected script must test "$1" and never contain "\$1".
	script := GetScpScript("test", "sb.domain.tld", "22")
	require.Contains(t, script, `elif [ "$1" = "-p" ] ;`, "the -p test must use $1, not a literal backslash")
	require.NotContains(t, script, `\$1`, "the script must not contain a literal-backslash $1")
}

func TestTOTPFile(t *testing.T) {

	expectedFile := `randomstring
" RATE_LIMIT 3 30 1589480337
" WINDOW_SIZE 17
" TOTP_AUTH
12
13
14
`

	require.Equal(t, expectedFile, GetTOTPFile("randomstring", []string{"12", "13", "14"}), "The GetTOTPFile() function returned an unexpected TOTP file")
}
