package config

import (
	"fmt"
	"os"

	"github.com/golgeek/sb/internal/types"
	"github.com/spf13/viper"
)

var (
	VERSION string
	COMMIT  string
)

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
			viper.SetDefault("general.encryption-key", "changemechangemechangemechangeme")

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
