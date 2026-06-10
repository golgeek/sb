package helpers

import (
	"reflect"
	"testing"
)

// TestHomeSkeletonCommands pins the exact privileged command plan of the home
// skeleton creation: which sudo commands run, in which order, with which
// argument shapes. The shapes double as a regression guard for the sudoers
// whitelist in templates.go — a command emitted here that the templates do
// not allow fails in production.
func TestHomeSkeletonCommands(t *testing.T) {

	tests := []struct {
		name     string
		homedir  string
		username string
		homeType string
		// exists is the injected pathExists probe result for every path.
		exists  bool
		want    [][]string
		wantErr bool
	}{
		{
			// pathExists returning false covers both "does not exist" and
			// "cannot be probed" (a non-root caller who cannot see inside
			// the new home): in both cases creation must be attempted, never
			// silently skipped. The latter is the regression case where
			// account creation by a non-root sb owner used to break.
			name:     "user skeleton on a fresh or unprobeable home creates everything",
			homedir:  "/home/t1000",
			username: "t1000",
			homeType: "user",
			exists:   false,
			want: [][]string{
				{"/usr/bin/sudo", "-u", "t1000", "/bin/mkdir", "/home/t1000/.ssh"},
				{"/usr/bin/sudo", "/bin/chmod", "0755", "/home/t1000/.ssh"},
				{"/usr/bin/sudo", "/bin/chown", "t1000:t1000", "/home/t1000/.ssh"},
				{"/usr/bin/sudo", "-u", "t1000", "/bin/mkdir", "/home/t1000/ttyrecs"},
				{"/usr/bin/sudo", "/bin/chmod", "0755", "/home/t1000/ttyrecs"},
				{"/usr/bin/sudo", "/bin/chown", "t1000:t1000", "/home/t1000/ttyrecs"},
				{"/usr/bin/sudo", "-u", "t1000", "/usr/bin/touch", "/home/t1000/accesses.db"},
				{"/usr/bin/sudo", "/bin/chmod", "0640", "/home/t1000/accesses.db"},
				{"/usr/bin/sudo", "/bin/chown", "t1000:t1000", "/home/t1000/accesses.db"},
				{"/usr/bin/sudo", "-u", "t1000", "/usr/bin/touch", "/home/t1000/logs.db"},
				{"/usr/bin/sudo", "/bin/chmod", "0640", "/home/t1000/logs.db"},
				{"/usr/bin/sudo", "/bin/chown", "t1000:t1000", "/home/t1000/logs.db"},
				{"/usr/bin/sudo", "-u", "t1000", "/usr/bin/touch", "/home/t1000/.ssh/authorized_keys"},
				{"/usr/bin/sudo", "/bin/chmod", "0640", "/home/t1000/.ssh/authorized_keys"},
				{"/usr/bin/sudo", "/bin/chown", "t1000:t1000", "/home/t1000/.ssh/authorized_keys"},
			},
		},
		{
			name:     "user skeleton on an existing home only converges modes and owners",
			homedir:  "/home/t1000",
			username: "t1000",
			homeType: "user",
			exists:   true,
			want: [][]string{
				{"/usr/bin/sudo", "/bin/chmod", "0755", "/home/t1000/.ssh"},
				{"/usr/bin/sudo", "/bin/chown", "t1000:t1000", "/home/t1000/.ssh"},
				{"/usr/bin/sudo", "/bin/chmod", "0755", "/home/t1000/ttyrecs"},
				{"/usr/bin/sudo", "/bin/chown", "t1000:t1000", "/home/t1000/ttyrecs"},
				{"/usr/bin/sudo", "/bin/chmod", "0640", "/home/t1000/accesses.db"},
				{"/usr/bin/sudo", "/bin/chown", "t1000:t1000", "/home/t1000/accesses.db"},
				{"/usr/bin/sudo", "/bin/chmod", "0640", "/home/t1000/logs.db"},
				{"/usr/bin/sudo", "/bin/chown", "t1000:t1000", "/home/t1000/logs.db"},
				{"/usr/bin/sudo", "/bin/chmod", "0640", "/home/t1000/.ssh/authorized_keys"},
				{"/usr/bin/sudo", "/bin/chown", "t1000:t1000", "/home/t1000/.ssh/authorized_keys"},
			},
		},
		{
			name:     "group skeleton on a fresh home creates everything",
			homedir:  "/home/bg_redteam",
			username: "bg_redteam",
			homeType: "group",
			exists:   false,
			want: [][]string{
				{"/usr/bin/sudo", "-u", "bg_redteam", "/bin/mkdir", "/home/bg_redteam/"},
				{"/usr/bin/sudo", "/bin/chmod", "0775", "/home/bg_redteam/"},
				{"/usr/bin/sudo", "/bin/chown", "bg_redteam:bg_redteam-aclk", "/home/bg_redteam/"},
				{"/usr/bin/sudo", "-u", "bg_redteam", "/bin/mkdir", "/home/bg_redteam/.ssh"},
				{"/usr/bin/sudo", "/bin/chmod", "0755", "/home/bg_redteam/.ssh"},
				{"/usr/bin/sudo", "/bin/chown", "bg_redteam:bg_redteam", "/home/bg_redteam/.ssh"},
				{"/usr/bin/sudo", "-u", "bg_redteam", "/usr/bin/touch", "/home/bg_redteam/accesses.db"},
				{"/usr/bin/sudo", "/bin/chmod", "0664", "/home/bg_redteam/accesses.db"},
				{"/usr/bin/sudo", "/bin/chown", "bg_redteam:bg_redteam-aclk", "/home/bg_redteam/accesses.db"},
			},
		},
		{
			name:     "unknown home type is refused",
			homedir:  "/home/x",
			username: "x",
			homeType: "device",
			wantErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := homeSkeletonCommands(tc.homedir, tc.username, tc.homeType, func(string) bool {
				return tc.exists
			})

			if tc.wantErr {
				if err == nil {
					t.Fatalf("homeSkeletonCommands() = nil error, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("homeSkeletonCommands() error = %v, want success", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("homeSkeletonCommands() plan mismatch:\ngot:  %v\nwant: %v", got, tc.want)
			}
		})
	}
}
