package cmd

import (
	"fmt"
	"net"
	"strings"

	"github.com/fatih/color"
	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/config"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"
)

// Info describes the info command
type Info struct {
}

func init() {
	commands.RegisterCommand("info", func() (c commands.Command, r models.Right, helper helpers.Helper, args map[string]commands.Argument) {
		return new(Info), models.Public, helpers.Helper{
			Header:      "display info on sb and your account",
			Usage:       "info",
			Description: "display info on sb and your account",
		}, map[string]commands.Argument{}
	})
}

// Checks checks whether or not the user can execute this method
func (c *Info) Checks(ct *commands.Context) error {
	// No specific rights needed but a sb account
	return nil
}

// Execute executes the command
func (c *Info) Execute(ct *commands.Context) (repl models.ReplicationData, cmdError error, err error) {

	users, err := models.GetAllSBUsers()
	if err != nil {
		return
	}
	groups, err := models.GetAllSBGroups()
	if err != nil {
		return
	}
	ipAddresses, err := c.getIPAddresses()
	if err != nil {
		return
	}
	// TOTP state is informational here, so a read error is reported inline rather
	// than aborting the whole info command.
	totpEnabled, _, totpEmergency, totpErr := ct.User.GetTOTP()

	green := color.New(color.FgGreen).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()

	fmt.Printf("Hi, %s!\n", green(ct.User.User.Username))
	fmt.Println()
	fmt.Printf("Here are a few information about the wonderful place you just connected to:\n")
	fmt.Printf("  -> my name is %s\n", green(config.GetSBName()))
	fmt.Printf("  -> I'm located in %s, my address is %s\n", green(config.GetSBLocation()), green(config.GetSBHostname()))
	fmt.Printf("  -> here is the list of my IP addresses: %s\n", green(strings.Join(ipAddresses, ", ")))
	fmt.Printf("  -> I currently have %s guests accounts\n", green(len(users)))
	fmt.Printf("  -> I'm currently hosting %s groups\n", green(len(groups)))
	fmt.Println()
	fmt.Printf("If you want to interact with me, just one of these aliases:\n")
	fmt.Printf("  -> SSH:  %s", green(fmt.Sprintf("alias %s='ssh %s@%s -t -A --'\n", config.GetSBName(), ct.User.User.Username, config.GetSBHostname())))
	fmt.Printf("  -> MOSH: %s", green(fmt.Sprintf("alias m%s='mosh %s@%s -A --'\n", config.GetSBName(), ct.User.User.Username, config.GetSBHostname())))
	fmt.Println()
	fmt.Printf("But let's talk a bit about yourself, %s!\n", green(ct.User.User.Username))
	fmt.Printf("  -> you're a member of %s groups\n", green(len(ct.User.Groups)))
	if ct.User.IsOwnerOfGroup("owners") {
		fmt.Printf("  -> as you're a member of the %s group, you have extra admin privileges\n", green("owners"))
		fmt.Printf("  -> FYI, I'm running version %s on commit %s\n", green(config.VERSION), green(config.COMMIT))
	}
	switch {
	case totpErr != nil:
		fmt.Printf("  -> TOTP status is %s (your configuration file could not be read)\n", red("unavailable"))
	case !totpEnabled:
		fmt.Printf("  -> TOTP is %s on your account\n", red("disabled"))
	default:
		fmt.Printf("  -> TOTP is %s on your account\n", green("enabled"))
		if len(totpEmergency) >= 3 {
			fmt.Printf("  -> you have %s unused emergency codes, feel free to generate new ones if you wish\n", green(len(totpEmergency)))
		} else {
			fmt.Printf("  -> you only have %s unused emergency codes left. %s\n", red(len(totpEmergency)), red("You should generate new ones right away!"))
		}
	}

	return
}

func (c *Info) PostExecute(repl models.ReplicationData) (err error) {
	return
}

func (c *Info) Replicate(repl models.ReplicationData) (err error) {
	return
}

func (c *Info) getIPAddresses() (ipAddresses []string, err error) {

	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}

	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			return ipAddresses, err
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			ipAddresses = append(ipAddresses, ip.String())
		}
	}

	return
}
