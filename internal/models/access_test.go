package models

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

type testBuildSBAccess struct {
	e testBuildSBAccessInputData
	o testBuildSBAccessOutputData
}
type testBuildSBAccessInputData struct {
	host            string
	user            string
	port            string
	alias           string
	strictHostCheck bool
}
type testBuildSBAccessOutputData struct {
	prefix string
	ip     string
	host   []string
	user   string
	port   int
	alias  string
	err    error
}

func TestBuildSBAccessWithIP(t *testing.T) {

	testValues := []testBuildSBAccess{
		{
			e: testBuildSBAccessInputData{
				host: "127.0.0.1", user: "root", port: "PORT", alias: "home", strictHostCheck: true,
			},
			o: testBuildSBAccessOutputData{
				err: fmt.Errorf("port is invalid"),
			},
		},
		{
			e: testBuildSBAccessInputData{
				host: "", user: "root", port: "22", alias: "home", strictHostCheck: true,
			},
			o: testBuildSBAccessOutputData{
				err: fmt.Errorf("host is missing"),
			},
		},
		{
			e: testBuildSBAccessInputData{
				host: "127.0.0.1", user: "root", port: "22", alias: "home", strictHostCheck: true,
			},
			o: testBuildSBAccessOutputData{
				ip: "127.0.0.1", prefix: "127.0.0.1/32", host: []string{"localhost"}, user: "root", port: 22, alias: "home",
			},
		},
		{
			e: testBuildSBAccessInputData{
				host: "::1", user: "root", port: "22", alias: "home", strictHostCheck: true,
			},
			o: testBuildSBAccessOutputData{
				ip: "::1", prefix: "::1/128", host: []string{"localhost", "ip6-localhost"}, user: "root", port: 22, alias: "home",
			},
		},
	}

	for _, testValue := range testValues {
		ba, err := BuildSBAccess(testValue.e.host, testValue.e.user, testValue.e.port, testValue.e.alias, testValue.e.strictHostCheck)

		if testValue.o.err == nil {
			require.NoError(t, err, "There was an unexpected error building sb access")
		} else {
			require.EqualError(t, err, testValue.o.err.Error(), "An error should have been returned")
			continue
		}

		require.Equal(t, testValue.o.prefix, ba.Prefix, "Prefix was not computed correctly")
		require.Contains(t, testValue.o.host, ba.Host, "Host was not computed correctly")
		require.Equal(t, testValue.o.user, ba.User, "User was not computed correctly")
		require.Equal(t, testValue.o.port, ba.Port, "Port was not computed correctly")
		require.Equal(t, testValue.o.alias, ba.Alias, "Alias was not reported correctly")
		require.Equal(t, testValue.o.ip, ba.IP.String(), "IP was not computed correctly")
	}
}

func TestBuildSBAccessWithOneIPRange(t *testing.T) {

	testValues := []testBuildSBAccess{
		{
			e: testBuildSBAccessInputData{
				host: "127.0.0.1/32", user: "root", port: "22", alias: "home", strictHostCheck: true,
			},
			o: testBuildSBAccessOutputData{
				ip: "127.0.0.1", prefix: "127.0.0.1/32", host: []string{"localhost"}, user: "root", port: 22, alias: "home",
			},
		},
		{
			e: testBuildSBAccessInputData{
				host: "::1/128", user: "root", port: "22", alias: "home", strictHostCheck: true,
			},
			o: testBuildSBAccessOutputData{
				ip: "::1", prefix: "::1/128", host: []string{"localhost", "ip6-localhost"}, user: "root", port: 22, alias: "home",
			},
		},
	}

	for _, testValue := range testValues {
		ba, err := BuildSBAccess(testValue.e.host, testValue.e.user, testValue.e.port, testValue.e.alias, testValue.e.strictHostCheck)

		if testValue.o.err == nil {
			require.NoError(t, err, "There was an unexpected error building sb access")
		} else {
			require.EqualError(t, err, testValue.o.err.Error(), "An error should have been returned")
			continue
		}

		require.Equal(t, testValue.o.prefix, ba.Prefix, "Prefix was not computed correctly")
		require.Contains(t, testValue.o.host, ba.Host, "Host was not computed correctly")
		require.Equal(t, testValue.o.user, ba.User, "User was not computed correctly")
		require.Equal(t, testValue.o.port, ba.Port, "Port was not computed correctly")
		require.Equal(t, testValue.o.alias, ba.Alias, "Alias was not reported correctly")
		require.Equal(t, testValue.o.ip, ba.IP.String(), "IP was not computed correctly")
	}
}

func TestBuildSBAccessWithRange(t *testing.T) {

	testValues := []testBuildSBAccess{
		{
			e: testBuildSBAccessInputData{
				host: "127.0.0.0/8", user: "root", port: "22", alias: "", strictHostCheck: true,
			},
			o: testBuildSBAccessOutputData{
				ip: "127.0.0.0", prefix: "127.0.0.0/8", host: []string{""}, user: "root", port: 22, alias: "",
			},
		},
		{
			e: testBuildSBAccessInputData{
				host: "::1/32", user: "root", port: "22", alias: "", strictHostCheck: true,
			},
			o: testBuildSBAccessOutputData{
				ip: "::1", prefix: "::/32", host: []string{""}, user: "root", port: 22, alias: "",
			},
		},
		{
			e: testBuildSBAccessInputData{
				host: "127.0.0.0/8", user: "root", port: "22", alias: "test", strictHostCheck: true,
			},
			o: testBuildSBAccessOutputData{
				err: fmt.Errorf("you cannot add an alias to an IP range"),
			},
		},
		{
			e: testBuildSBAccessInputData{
				host: "::1/32", user: "root", port: "22", alias: "test", strictHostCheck: true,
			},
			o: testBuildSBAccessOutputData{
				err: fmt.Errorf("you cannot add an alias to an IP range"),
			},
		},
	}

	for _, testValue := range testValues {
		ba, err := BuildSBAccess(testValue.e.host, testValue.e.user, testValue.e.port, testValue.e.alias, testValue.e.strictHostCheck)

		if testValue.o.err == nil {
			require.NoError(t, err, "There was an unexpected error building sb access")
		} else {
			require.EqualError(t, err, testValue.o.err.Error(), "An error should have been returned")
			continue
		}

		require.Equal(t, testValue.o.prefix, ba.Prefix, "Prefix was not computed correctly")
		require.Contains(t, testValue.o.host, ba.Host, "Host was not computed correctly")
		require.Equal(t, testValue.o.user, ba.User, "User was not computed correctly")
		require.Equal(t, testValue.o.port, ba.Port, "Port was not computed correctly")
		require.Equal(t, testValue.o.alias, ba.Alias, "Alias was not reported correctly")
		require.Equal(t, testValue.o.ip, ba.IP.String(), "IP was not computed correctly")
	}
}

func TestBuildSBAccessWithHost(t *testing.T) {

	testValues := []testBuildSBAccess{
		{
			e: testBuildSBAccessInputData{
				host: "localhost", user: "root", port: "22", alias: "home", strictHostCheck: true,
			},
			o: testBuildSBAccessOutputData{
				ip: "127.0.0.1", prefix: "127.0.0.1/32", host: []string{"localhost"}, user: "root", port: 22, alias: "home",
			},
		},
		{
			e: testBuildSBAccessInputData{
				host: "SHARK ATTACK", user: "root", port: "22", alias: "home", strictHostCheck: true,
			},
			o: testBuildSBAccessOutputData{
				err: fmt.Errorf("host is neither an IP, a prefix or a resolvable host"),
			},
		},
	}

	for _, testValue := range testValues {
		ba, err := BuildSBAccess(testValue.e.host, testValue.e.user, testValue.e.port, testValue.e.alias, testValue.e.strictHostCheck)

		if testValue.o.err == nil {
			require.NoError(t, err, "There was an unexpected error building sb access")
		} else {
			require.EqualError(t, err, testValue.o.err.Error(), "An error should have been returned")
			continue
		}

		require.Equal(t, testValue.o.prefix, ba.Prefix, "Prefix was not computed correctly")
		require.Contains(t, testValue.o.host, ba.Host, "Host was not computed correctly")
		require.Equal(t, testValue.o.user, ba.User, "User was not computed correctly")
		require.Equal(t, testValue.o.port, ba.Port, "Port was not computed correctly")
		require.Equal(t, testValue.o.alias, ba.Alias, "Alias was not reported correctly")
		require.Equal(t, testValue.o.ip, ba.IP.String(), "IP was not computed correctly")
	}
}

func TestBuildSBAccessWithAlias(t *testing.T) {

	testValues := []testBuildSBAccess{
		{
			e: testBuildSBAccessInputData{
				host: "test", user: "root", port: "22", alias: "", strictHostCheck: false,
			},
			o: testBuildSBAccessOutputData{
				ip: "<nil>", prefix: "", host: []string{"test"}, user: "root", port: 22, alias: "",
			},
		},
		{
			e: testBuildSBAccessInputData{
				host: "test", user: "root", port: "22", alias: "", strictHostCheck: true,
			},
			o: testBuildSBAccessOutputData{
				err: fmt.Errorf("host is neither an IP, a prefix or a resolvable host"),
			},
		},
	}

	for _, testValue := range testValues {
		ba, err := BuildSBAccess(testValue.e.host, testValue.e.user, testValue.e.port, testValue.e.alias, testValue.e.strictHostCheck)

		if testValue.o.err == nil {
			require.NoError(t, err, "There was an unexpected error building sb access")
		} else {
			require.EqualError(t, err, testValue.o.err.Error(), "An error should have been returned")
			continue
		}

		require.Equal(t, testValue.o.prefix, ba.Prefix, "Prefix was not computed correctly")
		require.Contains(t, testValue.o.host, ba.Host, "Host was not computed correctly")
		require.Equal(t, testValue.o.user, ba.User, "User was not computed correctly")
		require.Equal(t, testValue.o.port, ba.Port, "Port was not computed correctly")
		require.Equal(t, testValue.o.alias, ba.Alias, "Alias was not reported correctly")
		require.Equal(t, testValue.o.ip, ba.IP.String(), "IP was not computed correctly")
	}
}

type testSplitUserInput struct {
	e testSplitUserInputInputData
	o testSplitUserInputOutputData
}
type testSplitUserInputInputData struct {
	access          string
	strictHostCheck bool
}
type testSplitUserInputOutputData struct {
	host string
	user string
	port int
	err  error
}

func TestSplitUserInputStrict(t *testing.T) {

	testValues := []testSplitUserInput{
		{
			e: testSplitUserInputInputData{
				access: "root@test.com:22022", strictHostCheck: true,
			},
			o: testSplitUserInputOutputData{
				host: "test.com", user: "root", port: 22022,
			},
		},
		{
			e: testSplitUserInputInputData{
				access: "root@test.com", strictHostCheck: true,
			},
			o: testSplitUserInputOutputData{
				host: "test.com", user: "root", port: 0,
			},
		},
		{
			e: testSplitUserInputInputData{
				access: "root@test.com:port", strictHostCheck: true,
			},
			o: testSplitUserInputOutputData{
				err: fmt.Errorf("port is not a valid integer"),
			},
		},
		// IPv6: a port requires the standard bracketed form.
		{
			e: testSplitUserInputInputData{
				access: "root@[2001:db8::1]:2222", strictHostCheck: true,
			},
			o: testSplitUserInputOutputData{
				host: "2001:db8::1", user: "root", port: 2222,
			},
		},
		// IPv6: brackets without a port are accepted too.
		{
			e: testSplitUserInputInputData{
				access: "root@[::1]", strictHostCheck: true,
			},
			o: testSplitUserInputOutputData{
				host: "::1", user: "root", port: 0,
			},
		},
		// IPv6: a bare literal (no brackets) is a host without a port; its
		// colons must not be parsed as a port separator.
		{
			e: testSplitUserInputInputData{
				access: "root@::1", strictHostCheck: true,
			},
			o: testSplitUserInputOutputData{
				host: "::1", user: "root", port: 0,
			},
		},
		{
			e: testSplitUserInputInputData{
				access: "root@2001:db8::1", strictHostCheck: true,
			},
			o: testSplitUserInputOutputData{
				host: "2001:db8::1", user: "root", port: 0,
			},
		},
		// IPv6: the historical non-numeric-port error is preserved in the
		// bracketed form.
		{
			e: testSplitUserInputInputData{
				access: "root@[::1]:port", strictHostCheck: true,
			},
			o: testSplitUserInputOutputData{
				err: fmt.Errorf("port is not a valid integer"),
			},
		},
		// IPv6: an unclosed bracket is a parse error, not a silent guess.
		{
			e: testSplitUserInputInputData{
				access: "root@[::1:22", strictHostCheck: true,
			},
			o: testSplitUserInputOutputData{
				err: fmt.Errorf("unable to parse access from user input root@[::1:22: unclosed bracket in host"),
			},
		},
	}

	for _, testValue := range testValues {
		user, host, port, err := splitUserInput(testValue.e.access, testValue.e.strictHostCheck)

		if testValue.o.err == nil {
			require.NoError(t, err, "There was an unexpected error splitting user data")
		} else {
			require.EqualError(t, err, testValue.o.err.Error(), "An error should have been returned while splitting user data")
			continue
		}

		require.Equal(t, testValue.o.host, host, "Host was not computed correctly")
		require.Equal(t, testValue.o.user, user, "User was not computed correctly")
		require.Equal(t, testValue.o.port, port, "Port was not computed correctly")
	}

}

func TestSplitUserInputAlias(t *testing.T) {

	testValues := []testSplitUserInput{
		{
			e: testSplitUserInputInputData{
				access: "test", strictHostCheck: true,
			},
			o: testSplitUserInputOutputData{
				err: fmt.Errorf("unable to parse access from user input test: no @ separator found"),
			},
		},
		{
			e: testSplitUserInputInputData{
				access: "test", strictHostCheck: false,
			},
			o: testSplitUserInputOutputData{
				host: "test", user: "", port: 0,
			},
		},
		{
			e: testSplitUserInputInputData{
				access: "root@test", strictHostCheck: false,
			},
			o: testSplitUserInputOutputData{
				host: "test", user: "root", port: 0,
			},
		},
		{
			e: testSplitUserInputInputData{
				access: "root@test:22", strictHostCheck: false,
			},
			o: testSplitUserInputOutputData{
				host: "test", user: "root", port: 22,
			},
		},
		{
			e: testSplitUserInputInputData{
				access: "test:22", strictHostCheck: false,
			},
			o: testSplitUserInputOutputData{
				host: "test", user: "", port: 22,
			},
		},
		// IPv6 without a user part: bracketed with a port, and bare literals
		// of both short and full forms.
		{
			e: testSplitUserInputInputData{
				access: "[::1]:22", strictHostCheck: false,
			},
			o: testSplitUserInputOutputData{
				host: "::1", user: "", port: 22,
			},
		},
		{
			e: testSplitUserInputInputData{
				access: "::1", strictHostCheck: false,
			},
			o: testSplitUserInputOutputData{
				host: "::1", user: "", port: 0,
			},
		},
		{
			e: testSplitUserInputInputData{
				access: "2001:0db8:85a3:0000:0000:8a2e:0370:7334", strictHostCheck: false,
			},
			o: testSplitUserInputOutputData{
				host: "2001:0db8:85a3:0000:0000:8a2e:0370:7334", user: "", port: 0,
			},
		},
	}

	for _, testValue := range testValues {
		user, host, port, err := splitUserInput(testValue.e.access, testValue.e.strictHostCheck)

		if testValue.o.err == nil {
			require.NoError(t, err, "There was an unexpected error splitting user data")
		} else {
			require.EqualError(t, err, testValue.o.err.Error(), "An error should have been returned while splitting user data")
			continue
		}

		require.Equal(t, testValue.o.host, host, "Host was not computed correctly")
		require.Equal(t, testValue.o.user, user, "User was not computed correctly")
		require.Equal(t, testValue.o.port, port, "Port was not computed correctly")
	}

}

func TestIsIPv4(t *testing.T) {

	require.Equal(t, true, isIPv4("8.8.8.8"), "IP should be of IPv4 format")
	require.Equal(t, false, isIPv4("2001:0db8:85a3:0000:0000:8a2e:0370:7334"), "IP shouldn't be of IPv4 format")

}

// TestUniqueAccessesForHost pins the dedup behavior the egress commands
// (ttyrec, scp) rely on to decide whether the user's input names exactly one
// connection target.
func TestUniqueAccessesForHost(t *testing.T) {

	t.Run("duplicates collapse, order is preserved", func(t *testing.T) {
		a1 := &Access{Host: "h1", User: "root", Port: 22}
		a2 := &Access{Host: "h2", User: "root", Port: 22}
		dup := &Access{Host: "h1", User: "root", Port: 22}

		unique := UniqueAccessesForHost([]*Access{a1, a2, dup}, "typed.example.com")
		require.Equal(t, []*Access{a1, a2}, unique)
	})

	t.Run("same host with different user or port stays distinct", func(t *testing.T) {
		a1 := &Access{Host: "h1", User: "root", Port: 22}
		a2 := &Access{Host: "h1", User: "app", Port: 22}
		a3 := &Access{Host: "h1", User: "root", Port: 2222}

		unique := UniqueAccessesForHost([]*Access{a1, a2, a3}, "h1")
		require.Len(t, unique, 3)
	})

	t.Run("wide-prefix accesses take the typed host", func(t *testing.T) {
		// An access granted on a prefix is stored without a host; the typed
		// host completes it, and that completion participates in dedup: two
		// prefix grants for the same user/port collapse once completed.
		p1 := &Access{Host: "", User: "root", Port: 22}
		p2 := &Access{Host: "", User: "root", Port: 22}

		unique := UniqueAccessesForHost([]*Access{p1, p2}, "10.0.0.7")
		require.Len(t, unique, 1)
		require.Equal(t, "10.0.0.7", unique[0].Host, "the typed host must complete the wide-prefix access")
	})

	t.Run("completed prefix access deduplicates against an explicit grant", func(t *testing.T) {
		explicit := &Access{Host: "10.0.0.7", User: "root", Port: 22}
		prefix := &Access{Host: "", User: "root", Port: 22}

		unique := UniqueAccessesForHost([]*Access{explicit, prefix}, "10.0.0.7")
		require.Equal(t, []*Access{explicit}, unique)
	})

	t.Run("empty input yields an empty result", func(t *testing.T) {
		require.Empty(t, UniqueAccessesForHost(nil, "h1"))
	})
}

type testBuildSBAccessFromUserInput struct {
	e testSplitUserInputInputData
	o testBuildSBAccessOutputData
}

func TestBuildSBAccessFromUserInput(t *testing.T) {
	testValues := []testBuildSBAccessFromUserInput{
		{
			e: testSplitUserInputInputData{
				access: "root@127.0.0.1:22",
			},
			o: testBuildSBAccessOutputData{
				ip: "127.0.0.1", prefix: "127.0.0.1/32", host: []string{"localhost"}, user: "root", port: 22, alias: "",
			},
		},
		{
			e: testSplitUserInputInputData{
				access: "root@127.0.0.1",
			},
			o: testBuildSBAccessOutputData{
				ip: "127.0.0.1", prefix: "127.0.0.1/32", host: []string{"localhost"}, user: "root", port: 0, alias: "",
			},
		},
		{
			e: testSplitUserInputInputData{
				access: "root@localhost",
			},
			o: testBuildSBAccessOutputData{
				ip: "127.0.0.1", prefix: "127.0.0.1/32", host: []string{"localhost"}, user: "root", port: 0, alias: "",
			},
		},
		{
			e: testSplitUserInputInputData{
				access: "root@test",
			},
			o: testBuildSBAccessOutputData{
				ip: "<nil>", prefix: "", host: []string{"test"}, user: "root", port: 0, alias: "",
			},
		},
		{
			e: testSplitUserInputInputData{
				access: "test",
			},
			o: testBuildSBAccessOutputData{
				ip: "<nil>", prefix: "", host: []string{"test"}, user: "", port: 0, alias: "",
			},
		},
		{
			e: testSplitUserInputInputData{
				access: "@test",
			},
			o: testBuildSBAccessOutputData{
				ip: "<nil>", prefix: "", host: []string{"test"}, user: "", port: 0, alias: "",
			},
		},
		{
			e: testSplitUserInputInputData{
				access: "test:PORT",
			},
			o: testBuildSBAccessOutputData{
				err: fmt.Errorf("port is not a valid integer"),
			},
		},
	}

	for _, testValue := range testValues {
		ba, err := BuildSBAccessFromUserInput(testValue.e.access)

		if testValue.o.err == nil {
			require.NoError(t, err, "There was an unexpected error building access from user data")
		} else {
			require.EqualError(t, err, testValue.o.err.Error(), "An error should have been returned while building access from user data")
			continue
		}
		require.Equal(t, testValue.o.prefix, ba.Prefix, "Prefix was not computed correctly")
		require.Contains(t, testValue.o.host, ba.Host, "Host was not computed correctly")
		require.Equal(t, testValue.o.user, ba.User, "User was not computed correctly")
		require.Equal(t, testValue.o.port, ba.Port, "Port was not computed correctly")
		require.Equal(t, testValue.o.alias, ba.Alias, "Alias was not reported correctly")
		require.Equal(t, testValue.o.ip, ba.IP.String(), "IP was not computed correctly")
	}
}

func TestLoadInvalidSBAccess(t *testing.T) {
	_, err := LoadSBAccess("test.com", "root", "PORT", nil)
	require.Error(t, err, "port is invalid")

}

func TestString(t *testing.T) {
	ba, err := BuildSBAccess("test.com", "root", "22", "test", false)
	require.NoError(t, err, "There was an unexpected error while building sb access")
	require.Equal(t, "root@test.com:22 (test)", ba.ShortString(), "The short string function is not valid")

	ba, err = BuildSBAccess("test.com", "root", "", "", false)
	require.NoError(t, err, "There was an unexpected error while building sb access")
	require.Equal(t, "root@test.com", ba.ShortString(), "The short string function is not valid")

	ba, err = BuildSBAccess("test.com", "", "", "test", false)
	require.NoError(t, err, "There was an unexpected error while building sb access")
	require.Equal(t, "@test.com (test)", ba.ShortString(), "The short string function is not valid")

	expectedString := fmt.Sprintf("Prefix: %-20s | Host: %-20s | Alias: %-20s | User: %-10s | Port: %-5d", ba.Prefix, ba.Host, ba.Alias, ba.User, ba.Port)
	require.Equal(t, expectedString, ba.String(), "The expected string doesn't match the String() method")

	s := &Source{
		Type: "self",
	}
	require.Equal(t, "- personal access", s.String(), "The string function of Source is not valid")

	s = &Source{
		Type:  "group",
		Group: "Test",
	}
	require.Equal(t, "- group access from group Test", s.String(), "The string function of Source is not valid")
}

func TestIsAValidSBAccessFromUserInput(t *testing.T) {
	require.Equal(t, true, IsAValidSBAccessFromUserInput("test"), "Access is somewhat always valid")
}

func TestEquals(t *testing.T) {
	access, err := BuildSBAccess("test.com", "root", "22022", "test", true)
	require.NoError(t, err, "There was an unexpected error while building sb access")

	otherAccess, err := BuildSBAccess("test.com", "root", "22022", "test", true)
	require.NoError(t, err, "There was an unexpected error while building sb access")

	require.Equal(t, true, access.Equals(otherAccess), "The same two accesses should match")

	otherAccess.Port = 22
	require.Equal(t, false, access.Equals(otherAccess), "The ports of the accesses should differ")

	otherAccess.User = "test"
	require.Equal(t, false, access.Equals(otherAccess), "The users of the accesses should differ")

	otherAccess.Host = "meow.com"
	require.Equal(t, false, access.Equals(otherAccess), "The hosts of the accesses should differ")

}

func TestDBEndToEnd(t *testing.T) {

	// Get a database instance
	db, err := GetAccessGormDB(":memory:")
	require.NoError(t, err, "There was an unexpected error when getting database")
	require.IsType(t, &gorm.DB{}, db, "")

	// Build an access
	ba, err := BuildSBAccess("test.com", "root", "22022", "test", true)
	require.NoError(t, err, "There was an unexpected error while building sb access")

	baForUpdate, err := BuildSBAccess("meow.com", "root", "22022", "test", true)
	require.NoError(t, err, "There was an unexpected error while building sb access")

	// Save it to database
	err = ba.Save(db)
	require.NoError(t, err, "There was an unexpected error while saving a new access to database")

	// Load the access from the database
	baLoaded, err := LoadSBAccess("test.com", "root", "22022", db)
	require.NoError(t, err, "There was an unexpected error while loading access from database")

	// Check the object loaded still matches the object saved
	require.Equal(t, true, ba.Equals(baLoaded), "Access loaded from database should match the one saved!")

	// Modify the original object and save it
	ba.Prefix = baForUpdate.Prefix
	ba.Host = baForUpdate.Host
	ba.Port = baForUpdate.Port
	ba.User = baForUpdate.User
	err = ba.Save(db)
	require.NoError(t, err, "There was an unexpected error while saving an existing access to database")

	// Load the modified object from the database
	baModifiedLoaded, err := LoadSBAccess("meow.com", "root", "22022", db)
	require.NoError(t, err, "There was an unexpected error while loading the modified access from database")

	// Check the object loaded doesn't match the previous object saved
	require.Equal(t, false, baLoaded.Equals(baModifiedLoaded), "Host shouldn't match in comparaison!")

	// Load all accesses from database and check there is only one
	accesses, err := GetAllAccesses(db)
	require.NoError(t, err, "There was an unexpected error while loading all accesses from database")
	require.Equal(t, 1, len(accesses), "There should be one object in database")

	// Delete the object from database
	err = ba.Delete(db)
	require.NoError(t, err, "There was an unexpected error while deleting accesses from database")

	// Load all accesses from database and check there is none
	accesses, err = GetAllAccesses(db)
	require.NoError(t, err, "There was an unexpected error while loading all accesses from database")
	require.Equal(t, 0, len(accesses), "There should be one object in database")
}
