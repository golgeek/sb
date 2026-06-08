package helpers

import (
	"bytes"
	"text/template"
)

func getGroupSudoersTemplate(groupname string) (str string) {

	tpl := `# Owners' rights
%{{.}}-o		ALL=(root)		NOPASSWD: /usr/sbin/usermod -a -G {{.}} * 		# add a user as group's members
%{{.}}-o		ALL=(root)		NOPASSWD: /usr/sbin/usermod -a -G {{.}}-o * 		# add a user as group's owners
%{{.}}-o		ALL=(root)		NOPASSWD: /usr/sbin/usermod -a -G {{.}}-gk * 		# add a user as group's gate-keepers
%{{.}}-o		ALL=(root)		NOPASSWD: /usr/sbin/usermod -a -G {{.}}-aclk *		# add a user as group's acl-keepers
%{{.}}-o		ALL=(root)		NOPASSWD: /usr/sbin/deluser * {{.}}			# remove a user from the group's members
%{{.}}-o		ALL=(root)		NOPASSWD: /usr/sbin/deluser * {{.}}-o			# remove a user from the group's owners
%{{.}}-o		ALL=(root)		NOPASSWD: /usr/sbin/deluser * {{.}}-gk			# remove a user from the group's gate-keerps
%{{.}}-o		ALL=(root)		NOPASSWD: /usr/sbin/deluser * {{.}}-aclk			# remove a user from the group's acl-keepers
%{{.}}-o		ALL=({{.}})		NOPASSWD: /usr/bin/tee /home/{{.}}/.ssh/*			# create the private keypairs
%{{.}}-o		ALL=({{.}})		NOPASSWD: /bin/chmod 0600 /home/{{.}}/.ssh/*              # set the key private key as group readable
%{{.}}-o		ALL=({{.}})		NOPASSWD: /bin/chmod 0440 /home/{{.}}/.ssh/*              # set the key private key as group readable
%{{.}}-o		ALL=({{.}})		NOPASSWD: /bin/chmod 0644 /home/{{.}}/.ssh/*.pub              # set the key private key as group readable

# Gate keepers' rights
%{{.}}-gk	ALL=(root)		NOPASSWD: /usr/sbin/usermod -a -G {{.}} * 		# add a user as group's members
%{{.}}-gk	ALL=(root)		NOPASSWD: /usr/sbin/deluser * {{.}}			# remove a user from the group's members

# ACL keepers' rights
# No sudo commands here`

	t, err := template.New("tpl").Parse(tpl)
	if err != nil {
		panic(err)
	}
	out := new(bytes.Buffer)
	// The template and its data are static and trusted; a failure here is a
	// programming error, matching the panic on Parse above.
	if err := t.Execute(out, groupname); err != nil {
		panic(err)
	}

	return out.String()

}

func GetSystemdServiceFile(binaryPath, sbHomeDirectory string) (str string) {

	type systemdFile struct {
		BinaryPath      string
		SBHomeDirectory string
	}

	tplData := systemdFile{
		BinaryPath:      binaryPath,
		SBHomeDirectory: sbHomeDirectory,
	}

	tpl := `[Unit]
Description=sb
Wants=network-online.target
After=network-online.target NetworkManager-wait-online.service

[Service]
Type=simple
ExecStart=/bin/bash -c 'exec {{ .BinaryPath }} -d'
Restart=always
RestartPreventExitStatus=126
WorkingDirectory={{ .SBHomeDirectory }}
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=sb
User=root
Group=root
LimitNOFILE=795588

[Install]
WantedBy=multi-user.target`

	t, err := template.New("tpl").Parse(tpl)
	if err != nil {
		panic(err)
	}
	out := new(bytes.Buffer)
	// The template and its data are static and trusted; a failure here is a
	// programming error, matching the panic on Parse above.
	if err := t.Execute(out, tplData); err != nil {
		panic(err)
	}

	return out.String()
}

func GetGroupSudoersTemplateOwners(binaryPath, sbUser string) (str string) {

	type ownersSudoers struct {
		BinaryPath string
		SBUser     string
	}

	tplData := ownersSudoers{
		BinaryPath: binaryPath,
		SBUser:     sbUser,
	}

	tpl := `# Create a new sb group
%bg_owners-o	ALL=(root)	NOPASSWD: /usr/sbin/addgroup bg_*												# create the group
%bg_owners-o	ALL=(root)	NOPASSWD: /usr/sbin/adduser --home /home/bg_* --shell /usr/sbin/nologin --ingroup bg_* --disabled-password --gecos ?? bg_*	# add the user linked to the group
%bg_owners-o	ALL=(ALL)	NOPASSWD: /bin/chmod 0775 /home/bg_*												# chmod the group home directory
%bg_owners-o	ALL=(ALL)	NOPASSWD: /bin/chown * /home/bg_*												# chown the group home directory
%bg_owners-o	ALL=(root)	NOPASSWD: /usr/sbin/usermod -a -G bg_* *											# add the owner user to the group
%bg_owners-o	ALL=(ALL)	NOPASSWD: /bin/mkdir /home/bg_*/.ssh												# mkdir the .ssh directory
%bg_owners-o	ALL=(ALL)	NOPASSWD: /bin/chmod 0755 /home/bg_*/.ssh											# chmod the .ssh directory
%bg_owners-o	ALL=(ALL)	NOPASSWD: /bin/chown * /home/bg_*/.ssh												# chown the host file
%bg_owners-o	ALL=(ALL)	NOPASSWD: /usr/bin/touch /home/bg_*/accesses.db											# touch the host file
%bg_owners-o	ALL=(ALL)	NOPASSWD: /bin/chmod 0664 /home/bg_*/accesses.db										# chmod the host file
%bg_owners-o	ALL=(ALL)	NOPASSWD: /bin/chown * /home/bg_*/accesses.db											# chown the host file
%bg_owners-o	ALL=(root)	NOPASSWD: /usr/bin/tee /etc/sudoers.d/bg_*											# create the group's sudoers file
%bg_owners-o	ALL=(ALL)	NOPASSWD: /usr/bin/tee /home/bg_*/.ssh/*										# create the private keypairs
%bg_owners-o	ALL=(ALL)	NOPASSWD: /bin/chmod 0600 /home/bg_*/.ssh/*										# chmod the private keypairs
%bg_owners-o	ALL=(ALL)	NOPASSWD: /bin/chmod 0440 /home/bg_*/.ssh/*										# chmod the private keypairs
%bg_owners-o	ALL=(ALL)	NOPASSWD: /bin/chmod 0644 /home/bg_*/.ssh/*.pub 								# chmod the private keypairs

# Delete a sb group
%bg_owners-o	ALL=(root)	NOPASSWD: /usr/sbin/groupmod -n a_bg_*.bak_?????????? bg_*							# delete the group
%bg_owners-o	ALL=(root)	NOPASSWD: /usr/sbin/usermod -s /usr/sbin/nologin bg_*								# switch the group's user shell to /usr/sbin/nologin
%bg_owners-o	ALL=(root)	NOPASSWD: /usr/sbin/usermod -l bg_*.bak_?????????? bg_*						        # rename the group's user to user.bak
%bg_owners-o	ALL=(root)	NOPASSWD: /bin/mv /home/bg_* /home/bg_*.bak_??????????								# move the group's home to home.bak
%bg_owners-o	ALL=(root)	NOPASSWD: /bin/rm /etc/sudoers.d/bg_*												# remove the group's sudoers file

# Create a new sb user
%bg_owners-o	ALL=(root)	NOPASSWD: /usr/sbin/adduser --home /home/* --shell {{.BinaryPath}} --disabled-password --gecos ?? *			# create the account
%bg_owners-o	ALL=(ALL)	NOPASSWD: /bin/mkdir /home/*/.ssh												# mkdir the .ssh directory
%bg_owners-o	ALL=(ALL)	NOPASSWD: /bin/chmod 0755 /home/*/.ssh												# chmod the .ssh directory
%bg_owners-o	ALL=(ALL)	NOPASSWD: /bin/chown * /home/*/.ssh												# chown the host file
%bg_owners-o	ALL=(ALL)	NOPASSWD: /usr/bin/touch /home/*/.ssh/authorized_keys										# touch the authorized_keys file
%bg_owners-o	ALL=(ALL)	NOPASSWD: /bin/chmod 0640 /home/*/.ssh/authorized_keys										# chmod the authorized_keys file
%bg_owners-o	ALL=(ALL)	NOPASSWD: /bin/chown * /home/*/.ssh/authorized_keys										# chown the authorized_keys file
%bg_owners-o	ALL=(ALL)	NOPASSWD: /usr/bin/tee -a /home/*/.ssh/authorized_keys										# put the ingress SSH public key in the authorized_keys file
%bg_owners-o	ALL=(ALL)	NOPASSWD: /bin/mkdir /home/*/ttyrecs												# mkdir the ttyrecs directory
%bg_owners-o	ALL=(ALL)	NOPASSWD: /bin/chmod 0755 /home/*/ttyrecs											# chmod the ttyrecs directory
%bg_owners-o	ALL=(ALL)	NOPASSWD: /bin/chown * /home/*/ttyrecs												# chown the ttyrecs directory
%bg_owners-o	ALL=(ALL)	NOPASSWD: /usr/bin/touch /home/*/accesses.db											# touch the host file
%bg_owners-o	ALL=(ALL)	NOPASSWD: /bin/chmod 0640 /home/*/accesses.db											# chmod the host file
%bg_owners-o	ALL=(ALL)	NOPASSWD: /bin/chown * /home/*/accesses.db											# chown the host file
%bg_owners-o	ALL=(ALL)	NOPASSWD: /usr/bin/touch /home/*/logs.db											# touch the logs file
%bg_owners-o	ALL=(ALL)	NOPASSWD: /bin/chmod 0640 /home/*/logs.db											# chmod the logs file
%bg_owners-o	ALL=(ALL)	NOPASSWD: /bin/chown * /home/*/logs.db											# chown the logs file
%bg_owners-o	ALL=(root)	NOPASSWD: /usr/sbin/usermod -a -G {{.SBUser}} *											# add the owner user to the sb group

# Delete a sb user
%bg_owners-o	ALL=(root)	NOPASSWD: /usr/sbin/usermod -s /usr/sbin/nologin *									# switch the user shell to /usr/sbin/nologin
%bg_owners-o	ALL=(root)	NOPASSWD: /usr/sbin/usermod -l *.bak_?????????? *							        # rename the user to user.bak
%bg_owners-o	ALL=(root)	NOPASSWD: /usr/sbin/groupmod -n *.bak_?????????? *							        # delete the user's group to user.bak
%bg_owners-o	ALL=(root)	NOPASSWD: /bin/mv /home/* /home/*.bak_??????????									# move the user's home to home.bak

# Add a user to a group
%bg_owners-o	ALL=(root)	NOPASSWD: /usr/sbin/usermod -a -G bg_* *											# add the owner user to the group

# Remove a user from a group
%bg_owners-o    ALL=(root)      NOPASSWD: /usr/sbin/deluser * bg_*                                                                                              # delete the user linked to the group

# Create a new egress key for a group
%bg_owners-o	ALL=(ALL)	NOPASSWD: /usr/bin/ssh-keygen -t * -b * -N * -f /home/bg_*/.ssh/id_*_private.?????????? -C *					# generate a new key pair
%bg_owners-o	ALL=(ALL)	NOPASSWD: /bin/chmod 440 /home/bg_*/.ssh/*											# set the key private key as group readable`

	t, err := template.New("tpl").Parse(tpl)
	if err != nil {
		panic(err)
	}
	out := new(bytes.Buffer)
	// The template and its data are static and trusted; a failure here is a
	// programming error, matching the panic on Parse above.
	if err := t.Execute(out, tplData); err != nil {
		panic(err)
	}

	return out.String()
}

// GetScpScript returns the user's SCP script
func GetScpScript(user, host, port string) (str string) {

	type scpScript struct {
		User string
		Port string
		Host string
	}

	tplData := scpScript{
		User: user,
		Port: port,
		Host: host,
	}

	// The wrapper is invoked by the client's scp/sftp as the ssh replacement
	// program: "<this> <ssh-options> -- <host> <command>". It collects the ssh
	// options, extracts the login user / port, and detects whether the client is
	// asking for the SFTP subsystem (ssh -s ... host sftp) or the legacy SCP
	// sub-protocol (... host "scp -t/-f ..."), then re-invokes ssh into sb with
	// the matching mode. sb stays a transparent pipe, so the single alias
	// "scp -S ~/.<name>scp" (no -O) works for both modern (SFTP) and pre-9.0
	// (legacy SCP) clients.
	tpl := `#! /bin/sh
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
	exec ssh -p {{.Port}} {{.User}}@{{.Host}} $sshcmdline -T -- scp --access $host --scp-cmd sftp
else
	exec ssh -p {{.Port}} {{.User}}@{{.Host}} $sshcmdline -T -- scp --access $host --scp-cmd "\"$3\""
fi
`

	t, err := template.New("tpl").Parse(tpl)
	if err != nil {
		panic(err)
	}
	out := new(bytes.Buffer)
	// The template and its data are static and trusted; a failure here is a
	// programming error, matching the panic on Parse above.
	if err := t.Execute(out, tplData); err != nil {
		panic(err)
	}

	return out.String()

}

// GetTOTPFile returns the user's TOTP file
func GetTOTPFile(secret string, emergencyCodes []string) (str string) {

	type scpScript struct {
		Secret string
		Codes  []string
	}

	tplData := scpScript{
		Secret: secret,
		Codes:  emergencyCodes,
	}

	tpl := `{{.Secret}}
" RATE_LIMIT 3 30 1589480337
" WINDOW_SIZE 17
" TOTP_AUTH
{{range .Codes}}{{.}}
{{end}}`

	t, err := template.New("tpl").Parse(tpl)
	if err != nil {
		panic(err)
	}
	out := new(bytes.Buffer)
	// The template and its data are static and trusted; a failure here is a
	// programming error, matching the panic on Parse above.
	if err := t.Execute(out, tplData); err != nil {
		panic(err)
	}

	return out.String()

}
