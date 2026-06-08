package helpers

import (
	"bytes"
	"fmt"
)

// hostKeyMismatchMarkers are the distinctive strings OpenSSH prints to stderr
// when an egress connection is refused because the distant host presented a key
// that does not match the one pinned in known_hosts (StrictHostKeyChecking
// catching a changed key). Matching on these lets us surface a recovery hint to
// the user instead of leaving them with a raw, scary ssh error.
var hostKeyMismatchMarkers = [][]byte{
	[]byte("REMOTE HOST IDENTIFICATION HAS CHANGED"),
	[]byte("Host key verification failed"),
}

// hostKeyWatcherTailLen is the number of trailing bytes the watcher retains
// between writes so that a marker split across two Write calls is still found.
// It is comfortably larger than the longest marker above.
const hostKeyWatcherTailLen = 256

// HostKeyWatcher is an io.Writer meant to be tee'd alongside the egress SSH
// process's stderr. It scans the byte stream for the host-key-mismatch markers
// without buffering the whole (potentially large) stream: it keeps only a small
// trailing window between writes so markers straddling a write boundary are
// still detected. Once a marker is seen it latches Triggered to true and stops
// scanning. Write never errors, so it never interferes with the real stderr
// copy it shadows.
type HostKeyWatcher struct {
	triggered bool
	tail      []byte
}

// Write scans p (combined with the retained tail) for any mismatch marker and
// latches the triggered state. It always reports the full length as written and
// a nil error so it is safe to use as one leg of an io.MultiWriter shadowing
// the real stderr.
func (w *HostKeyWatcher) Write(p []byte) (n int, err error) {
	if !w.triggered {
		scan := make([]byte, 0, len(w.tail)+len(p))
		scan = append(scan, w.tail...)
		scan = append(scan, p...)

		for _, marker := range hostKeyMismatchMarkers {
			if bytes.Contains(scan, marker) {
				w.triggered = true
				w.tail = nil
				break
			}
		}

		if !w.triggered {
			// Retain only the trailing window for the next write so a marker
			// spanning the boundary is still caught, keeping memory bounded.
			if len(scan) > hostKeyWatcherTailLen {
				scan = scan[len(scan)-hostKeyWatcherTailLen:]
			}
			w.tail = append(w.tail[:0], scan...)
		}
	}
	return len(p), nil
}

// Triggered reports whether a host-key-mismatch marker has been seen so far.
func (w *HostKeyWatcher) Triggered() bool {
	return w.triggered
}

// knownHostsToken returns the token that identifies the distant host in a
// known_hosts file, matching how OpenSSH stores and how `ssh-keygen -R` removes
// it: a bare hostname for the default SSH port (22), or the bracketed
// "[host]:port" form for any non-standard port.
func knownHostsToken(host string, port int) string {
	if port == 22 {
		return host
	}
	return fmt.Sprintf("[%s]:%d", host, port)
}

// HostKeyMismatchHint builds the message shown to a user whose egress
// connection was refused because the distant host's key changed since it was
// pinned. It explains the situation and hands back a ready-to-paste command
// (run from the user's own machine, back through this bastion) that clears the
// stale pin via the existing "self hostkey forget" command, gated behind an
// explicit "only if you trust this change" warning so a real man-in-the-middle
// is not waved through.
//
//	sbUser/sbHost/sbPort describe how the user reaches this bastion.
//	targetHost/targetPort describe the distant host that failed verification.
func HostKeyMismatchHint(sbUser, sbHost, sbPort, targetHost string, targetPort int) string {
	token := knownHostsToken(targetHost, targetPort)
	return fmt.Sprintf(`
⚠ Host key verification FAILED for %s: the host key changed since it was pinned.
  This can be a legitimate host rebuild/rekey — or a man-in-the-middle attack.
  ONLY if you trust this change, clear the stored key by running from your machine:

      ssh -p %s %s@%s "self hostkey forget --hostkey '%s'"

  then reconnect. Do NOT run it if you did not expect the host key to change.
`, token, sbPort, sbUser, sbHost, token)
}
