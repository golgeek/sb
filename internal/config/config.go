package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/golgeek/sb/internal/types"
	"github.com/spf13/viper"
)

var (
	VERSION string
	COMMIT  string
)

// DefaultEncryptionKey is the placeholder value shipped as the default for
// general.encryption-key. It is intentionally a well-known string so that a
// fresh install starts, but it must be changed before any feature that uses it
// to protect secrets at rest or in transit is enabled. The same constant is
// reused by the startup validation below so the two never drift apart.
const DefaultEncryptionKey = "changemechangemechangemechangeme"

// Initialize initializes the viper config and sets default values
func init() {

	viper.SetConfigName("sb")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("/etc/sb")

	err := viper.ReadInConfig()
	if err != nil {

		if _, ok := err.(viper.ConfigFileNotFoundError); ok {

			// General instance configuration
			viper.SetDefault("general.name", "sb")
			viper.SetDefault("general.location", "earth")
			viper.SetDefault("general.hostname", "sb.domain.tld")
			viper.SetDefault("general.binary_path", "/opt/sb/sb")
			viper.SetDefault("general.ssh_port", "22")
			viper.SetDefault("general.mosh_ports_range", "40000:49999")
			viper.SetDefault("general.env_vars_to_forward", []string{"USER"})
			viper.SetDefault("general.sb_user", "sb")
			viper.SetDefault("general.sb_user_home", "/home/sb")
			viper.SetDefault("general.encryption-key", DefaultEncryptionKey)
			viper.SetDefault("general.egress_strict_host_key_checking", defaultEgressStrictHostKeyChecking)

			// Commands configuration
			viper.SetDefault("commands.ssh_command", "ttyrec")

			// Replication configuration
			viper.SetDefault("replication.enabled", false)
			viper.SetDefault("replication.queue.type", "")
			viper.SetDefault("replication.queue.googlepubsub.project", "")
			viper.SetDefault("replication.queue.googlepubsub.topic", "")

			// TTYrecs offloading configuration
			viper.SetDefault("ttyrecsoffloading.enabled", false)
			viper.SetDefault("ttyrecsoffloading.storage.type", "")
			viper.SetDefault("ttyrecsoffloading.storage.gcs.bucket", "")
			viper.SetDefault("ttyrecsoffloading.storage.gcs.objects-base-path", "")
			viper.SetDefault("ttyrecsoffloading.storage.gcs.endpoint-url", "")
			viper.SetDefault("ttyrecsoffloading.storage.s3.bucket", "")
			viper.SetDefault("ttyrecsoffloading.storage.s3.keys-base-path", "")

		} else {

			os.Exit(-1)

		}
	}
}

// GetSBName returns sb's name (AKA the alias to set in user's path)
func GetSBName() string {
	return viper.GetString("general.name")
}

// GetSBLocation returns sb's location (AKA the specific instance in a replicated set)
func GetSBLocation() string {
	return viper.GetString("general.location")
}

// GetSBHostname returns sb's hostname
func GetSBHostname() string {
	return viper.GetString("general.hostname")
}

// GetSSHCommand returns the SSH command to launch when user wants to access a host
func GetSSHCommand() string {
	return viper.GetString("commands.ssh_command")
}

// GetMOSHPortsRange returns the MOSH server ports range
func GetMOSHPortsRange() string {
	return viper.GetString("general.mosh_ports_range")
}

// GetSSHPort returns the SSH server port
func GetSSHPort() string {
	return viper.GetString("general.ssh_port")
}

// GetEnvironmentVarsToForward returns the list of environment variables to forward to distant hosts
func GetEnvironmentVarsToForward() []string {
	return viper.GetStringSlice("general.env_vars_to_forward")
}

// GetBinaryPath returns the path of the sb binary
func GetBinaryPath() string {
	return viper.GetString("general.binary_path")
}

// GetSBUsername returns the global sb user name
func GetSBUsername() string {
	return viper.GetString("general.sb_user")
}

// GetSBUserHome returns the global sb user home
func GetSBUserHome() string {
	return viper.GetString("general.sb_user_home")
}

// GetGlobalDatabasePath returns the global database path
func GetGlobalDatabasePath() string {
	return fmt.Sprintf("%s/logs.db", GetSBUserHome())
}

// GetReplicationDatabasePath returns the global database path
func GetReplicationDatabasePath() string {
	return fmt.Sprintf("%s/replication.db", GetSBUserHome())
}

// GetEncryptionKey returns the symmetric encryption key for backup, replication and ttyrecs offloading
func GetEncryptionKey() string {
	return viper.GetString("general.encryption-key")
}

// EncryptionKeyIsInsecure reports whether the configured encryption key offers
// no real protection: it is true when the key is empty or still set to the
// shipped placeholder (DefaultEncryptionKey). A key in either state is, in
// practice, public knowledge, so anything encrypted with it must be treated as
// plaintext.
func EncryptionKeyIsInsecure() bool {
	key := GetEncryptionKey()
	return key == "" || key == DefaultEncryptionKey
}

// validEncryptionKeyByteLengths are the byte lengths AES accepts as a key
// (AES-128, AES-192 and AES-256 respectively). general.encryption-key is used
// directly as the AES key on the replication transport path
// (models.EncryptReplicationDataForTransport), so it must be exactly one of
// these. The file-encryption path (offloaded ttyrecs, backups) derives its key
// via HKDF and so tolerates any non-empty length, but the documented contract
// for general.encryption-key — and the startup guard below — require a valid
// AES length whenever any feature that uses the key is enabled.
var validEncryptionKeyByteLengths = map[int]bool{16: true, 24: true, 32: true}

// EncryptionKeyHasValidLength reports whether key has a byte length usable as an
// AES key (16, 24 or 32 bytes). It is the single source of truth shared by the
// startup guard (ValidateSecretsEncryption) and the replication transport, so
// the guard never accepts a key the transport would later reject.
func EncryptionKeyHasValidLength(key string) bool {
	return validEncryptionKeyByteLengths[len(key)]
}

// ValidateSecretsEncryption fails closed when a feature that uses the
// encryption key to protect secrets is enabled while the key is unusable:
// either insecure (empty or the shipped default) or set to a value AES cannot
// use as a key (not 16, 24 or 32 bytes).
//
// The key protects two flows that move secrets off the host: replication
// payloads (which carry TOTP secrets and recovery codes) pushed to the queue,
// and TTYRec recordings offloaded to object storage. If neither flow is
// enabled the key never guards anything that leaves the host, so its value does
// not matter and this returns nil.
//
// When at least one flow is enabled it enforces, in order:
//   - the key is not effectively public (empty or the shipped default), and
//   - the key is a valid AES length.
//
// The length check matters because without it the daemon would start and only
// fail later, mid-flight, when the replication path calls aes.NewCipher — after
// secrets have already been queued. Both errors name the offending feature(s)
// so the operator can fix general.encryption-key before any secret is shipped.
//
// It returns nil when the configuration is safe and a descriptive error
// otherwise.
func ValidateSecretsEncryption() error {
	var enabledFeatures []string
	if GetReplicationEnabled() {
		enabledFeatures = append(enabledFeatures, "replication")
	}
	if GetTTYRecsOffloadingConfig().Enabled {
		enabledFeatures = append(enabledFeatures, "ttyrecs offloading")
	}

	if len(enabledFeatures) == 0 {
		return nil
	}
	features := strings.Join(enabledFeatures, " and ")

	if EncryptionKeyIsInsecure() {
		return fmt.Errorf(
			"refusing to start: %s enabled but general.encryption-key is unset or still the default placeholder; "+
				"these features encrypt secrets (TOTP secrets, recovery codes, session recordings) that leave this host, "+
				"so set general.encryption-key to a unique 16, 24 or 32-byte value (shared across replicated instances) first",
			features,
		)
	}

	if !EncryptionKeyHasValidLength(GetEncryptionKey()) {
		return fmt.Errorf(
			"refusing to start: %s enabled but general.encryption-key is %d bytes; "+
				"it must be exactly 16, 24 or 32 bytes (AES-128/192/256) to be usable as an encryption key",
			features, len(GetEncryptionKey()),
		)
	}

	return nil
}

// defaultEgressStrictHostKeyChecking is the fallback host-key policy for the
// egress hop. It is also registered with viper.SetDefault, but that default only
// applies when sb runs with no config file at all; real deployments always have
// one, so the accessor below must not depend on it.
const defaultEgressStrictHostKeyChecking = "accept-new"

// GetEgressStrictHostKeyChecking returns the value passed to the egress SSH
// hop's -oStrictHostKeyChecking option (bastion -> distant host).
//
// It defaults to "accept-new": the first time a distant host is seen its key is
// pinned in the user's managed known_hosts, and any later key change is refused
// (TOFU-with-pinning). Operators who pre-provision host keys out of band can
// tighten this to "yes" to refuse any unknown host; "no" disables verification
// entirely and is strongly discouraged. The value is passed verbatim to ssh.
//
// An empty value is treated as unset and falls back to the default. This is
// deliberate: viper's SetDefault only takes effect when no config file is
// present, but existing deployments have a config file that predates this key,
// so the value would be empty there — and emitting "-oStrictHostKeyChecking="
// makes ssh abort with "no argument after keyword". Falling back here keeps
// those deployments working and never produces an empty option.
func GetEgressStrictHostKeyChecking() string {
	if policy := viper.GetString("general.egress_strict_host_key_checking"); policy != "" {
		return policy
	}
	return defaultEgressStrictHostKeyChecking
}

func GetReplicationEnabled() bool {
	return viper.GetBool("replication.enabled")
}

func GetReplicationQueueConfig() *types.ReplicationQueueConfig {
	return &types.ReplicationQueueConfig{
		Enabled:      viper.GetBool("replication.enabled"),
		QueueType:    viper.GetString("replication.queue.type"),
		QueueOptions: viper.Sub(fmt.Sprintf("replication.queue.%s", viper.GetString("replication.queue.type"))),
	}
}

func GetTTYRecsOffloadingConfig() *types.TTYRecsOffloadingConfig {
	return &types.TTYRecsOffloadingConfig{
		Enabled:        viper.GetBool("ttyrecsoffloading.enabled"),
		StorageType:    viper.GetString("ttyrecsoffloading.storage.type"),
		StorageOptions: viper.Sub(fmt.Sprintf("ttyrecsoffloading.storage.%s", viper.GetString("ttyrecsoffloading.storage.type"))),
	}
}
