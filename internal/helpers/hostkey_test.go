package helpers

import (
	"strings"
	"testing"
)

// TestHostKeyWatcher exercises the streaming detector: it must latch on either
// OpenSSH mismatch marker, find a marker even when it is split across two
// writes, and stay quiet on benign output.
func TestHostKeyWatcher(t *testing.T) {
	t.Run("detects changed-identification banner", func(t *testing.T) {
		w := &HostKeyWatcher{}
		_, _ = w.Write([]byte("@@@@@@@@@@\nWARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\n"))
		if !w.Triggered() {
			t.Fatal("expected watcher to trigger on the changed-identification banner")
		}
	})

	t.Run("detects verification-failed line", func(t *testing.T) {
		w := &HostKeyWatcher{}
		_, _ = w.Write([]byte("Host key verification failed.\r\n"))
		if !w.Triggered() {
			t.Fatal("expected watcher to trigger on the verification-failed line")
		}
	})

	t.Run("detects a marker split across writes", func(t *testing.T) {
		w := &HostKeyWatcher{}
		_, _ = w.Write([]byte("Host key verifi"))
		_, _ = w.Write([]byte("cation failed."))
		if !w.Triggered() {
			t.Fatal("expected watcher to trigger on a marker spanning two writes")
		}
	})

	t.Run("ignores benign output", func(t *testing.T) {
		w := &HostKeyWatcher{}
		_, _ = w.Write([]byte("Welcome to the distant host\nlast login: yesterday\n"))
		if w.Triggered() {
			t.Fatal("did not expect the watcher to trigger on benign output")
		}
	})

	t.Run("write reports full length and no error", func(t *testing.T) {
		w := &HostKeyWatcher{}
		payload := []byte("some bytes")
		n, err := w.Write(payload)
		if err != nil {
			t.Fatalf("Write returned an error: %s", err)
		}
		if n != len(payload) {
			t.Fatalf("Write reported %d bytes, want %d", n, len(payload))
		}
	})
}

// TestHostKeyMismatchHint checks that the recovery hint embeds a copy-pasteable
// forget command with the correct known_hosts token: a bare host on port 22 and
// the bracketed [host]:port form otherwise.
func TestHostKeyMismatchHint(t *testing.T) {
	t.Run("default port uses bare host token", func(t *testing.T) {
		hint := HostKeyMismatchHint("alice", "bastion.example.com", "22", "prod-web", 22)
		if !strings.Contains(hint, "self hostkey forget --hostkey 'prod-web'") {
			t.Fatalf("hint missing bare-host forget command:\n%s", hint)
		}
		if !strings.Contains(hint, "ssh -p 22 alice@bastion.example.com") {
			t.Fatalf("hint missing bastion ssh invocation:\n%s", hint)
		}
	})

	t.Run("non-default port uses bracketed token", func(t *testing.T) {
		hint := HostKeyMismatchHint("alice", "bastion.example.com", "2222", "prod-db", 2022)
		if !strings.Contains(hint, "self hostkey forget --hostkey '[prod-db]:2022'") {
			t.Fatalf("hint missing bracketed forget command:\n%s", hint)
		}
		if !strings.Contains(hint, "ssh -p 2222 alice@bastion.example.com") {
			t.Fatalf("hint missing bastion ssh invocation with custom port:\n%s", hint)
		}
	})
}
