package commands

import (
	"errors"
	osuser "os/user"
	"strings"
	"testing"

	"github.com/golgeek/sb/internal/models"
)

// testUser builds a models.User suitable for hermetic authorization tests: a
// plain os/user identity plus an explicit group-membership map, with no system
// lookup involved.
func testUser(username, uid string, groups map[string]*models.Group) *models.User {
	return &models.User{
		User:   &osuser.User{Username: username, Uid: uid},
		Groups: groups,
	}
}

// group is a shorthand to declare a named group with the given role flags in a
// user's membership map.
func group(name string, member, aclKeeper, gateKeeper, owner bool) *models.Group {
	return &models.Group{
		Name:       name,
		Member:     member,
		ACLKeeper:  aclKeeper,
		GateKeeper: gateKeeper,
		Owner:      owner,
	}
}

// testContext builds a Context for authorization tests. The embedded Log has
// no databases attached, so the audit writes performed by authorize are
// exercised but never touch the filesystem. Allowed is pre-set to true so a
// test can detect that a refusal explicitly flipped it to false (the zero
// value could not distinguish "flipped" from "never written").
func testContext(user *models.User, grp *models.Group, args map[string]string) *Context {
	return &Context{
		User:               user,
		Log:                &models.Log{Allowed: true},
		Group:              grp,
		FormattedArguments: args,
	}
}

// TestAuthorize covers the full authorization matrix: every rights level, the
// "owners" super-group escalations, the root/UID-0 special cases, the
// fail-closed paths (group-scoped level without a group, unrecognized rights
// level), and the audit-log side effects of refusals.
func TestAuthorize(t *testing.T) {

	// memberGroups is a membership map for a user who is a plain member of
	// "team" (no ACL-keeper/gate-keeper/owner roles anywhere).
	memberGroups := map[string]*models.Group{
		"team": group("team", true, false, false, false),
	}

	team := &models.Group{Name: "team"}

	tests := []struct {
		name   string
		rights models.Right
		user   *models.User
		group  *models.Group // resolved --group target, nil when absent
		// wantErr is the exact error message expected, empty for success.
		wantErr string
		// wantAllowedFlipped asserts the refusal marked the audit log
		// not-allowed (the test context pre-sets Allowed to true).
		wantAllowedFlipped bool
	}{
		{
			name:   "public allows anyone",
			rights: models.Public,
			user:   testUser("alice", "1000", nil),
		},
		{
			name:   "private allows root",
			rights: models.Private,
			user:   testUser("root", "0", nil),
		},
		{
			name:               "private refuses non-root",
			rights:             models.Private,
			user:               testUser("alice", "1000", nil),
			wantErr:            "only root user can execute this command on sb",
			wantAllowedFlipped: true,
		},
		{
			name:   "group member allows member",
			rights: models.GroupMember,
			user:   testUser("alice", "1000", memberGroups),
			group:  team,
		},
		{
			name:               "group member refuses non-member",
			rights:             models.GroupMember,
			user:               testUser("alice", "1000", nil),
			group:              team,
			wantErr:            "user is not a member of the group",
			wantAllowedFlipped: true,
		},
		{
			// Roles are independent flags (each maps to its own system
			// group), so holding the owner role does not imply the member
			// flag — and the member level must check exactly that flag.
			name:   "group member refuses owner without the member flag",
			rights: models.GroupMember,
			user: testUser("alice", "1000", map[string]*models.Group{
				"team": group("team", false, false, false, true),
			}),
			group:              team,
			wantErr:            "user is not a member of the group",
			wantAllowedFlipped: true,
		},
		{
			name:               "group member refuses member of another group",
			rights:             models.GroupMember,
			user:               testUser("alice", "1000", memberGroups),
			group:              &models.Group{Name: "other"},
			wantErr:            "user is not a member of the group",
			wantAllowedFlipped: true,
		},
		{
			name:   "group ACL keeper allows ACL keeper",
			rights: models.GroupACLKeeper,
			user: testUser("alice", "1000", map[string]*models.Group{
				"team": group("team", true, true, false, false),
			}),
			group: team,
		},
		{
			name:               "group ACL keeper refuses plain member",
			rights:             models.GroupACLKeeper,
			user:               testUser("alice", "1000", memberGroups),
			group:              team,
			wantErr:            "user is not an ACL keeper of the group",
			wantAllowedFlipped: true,
		},
		{
			name:   "group gate keeper allows gate keeper",
			rights: models.GroupGateKeeper,
			user: testUser("alice", "1000", map[string]*models.Group{
				"team": group("team", true, false, true, false),
			}),
			group: team,
		},
		{
			name:               "group gate keeper refuses plain member",
			rights:             models.GroupGateKeeper,
			user:               testUser("alice", "1000", memberGroups),
			group:              team,
			wantErr:            "user is not a gate keeper of the group",
			wantAllowedFlipped: true,
		},
		{
			name:   "group owner allows owner of the group",
			rights: models.GroupOwner,
			user: testUser("alice", "1000", map[string]*models.Group{
				"team": group("team", true, false, false, true),
			}),
			group: team,
		},
		{
			name:   "group owner allows owner of the owners super-group",
			rights: models.GroupOwner,
			user: testUser("alice", "1000", map[string]*models.Group{
				"owners": group("owners", true, false, false, true),
			}),
			group: team,
		},
		{
			name:               "group owner refuses plain member",
			rights:             models.GroupOwner,
			user:               testUser("alice", "1000", memberGroups),
			group:              team,
			wantErr:            "user is not an owner of the group",
			wantAllowedFlipped: true,
		},
		{
			name:   "group owner refuses mere member of the owners group",
			rights: models.GroupOwner,
			user: testUser("alice", "1000", map[string]*models.Group{
				"owners": group("owners", true, false, false, false),
			}),
			group:              team,
			wantErr:            "user is not an owner of the group",
			wantAllowedFlipped: true,
		},
		{
			name:   "sb owner allows owner of the owners super-group",
			rights: models.SBOwner,
			user: testUser("alice", "1000", map[string]*models.Group{
				"owners": group("owners", true, false, false, true),
			}),
		},
		{
			name:   "sb owner allows UID 0",
			rights: models.SBOwner,
			user:   testUser("root", "0", nil),
		},
		{
			name:               "sb owner refuses regular user",
			rights:             models.SBOwner,
			user:               testUser("alice", "1000", memberGroups),
			wantErr:            "user is not a sb owner",
			wantAllowedFlipped: true,
		},
		{
			name:               "group member without resolved group fails closed",
			rights:             models.GroupMember,
			user:               testUser("alice", "1000", memberGroups),
			wantErr:            "this command requires a group, but none was provided",
			wantAllowedFlipped: true,
		},
		{
			name:               "group ACL keeper without resolved group fails closed",
			rights:             models.GroupACLKeeper,
			user:               testUser("alice", "1000", memberGroups),
			wantErr:            "this command requires a group, but none was provided",
			wantAllowedFlipped: true,
		},
		{
			name:               "group gate keeper without resolved group fails closed",
			rights:             models.GroupGateKeeper,
			user:               testUser("alice", "1000", memberGroups),
			wantErr:            "this command requires a group, but none was provided",
			wantAllowedFlipped: true,
		},
		{
			name:               "group owner without resolved group fails closed",
			rights:             models.GroupOwner,
			user:               testUser("alice", "1000", memberGroups),
			wantErr:            "this command requires a group, but none was provided",
			wantAllowedFlipped: true,
		},
		{
			name:               "unrecognized rights level fails closed",
			rights:             models.Right(9999),
			user:               testUser("root", "0", nil),
			wantErr:            "unrecognized rights level 9999: refusing execution",
			wantAllowedFlipped: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ct := testContext(tc.user, tc.group, nil)

			err := newAuthorizer().authorize(tc.user, tc.rights, ct)

			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("authorize() = %q, want success", err)
				}
				if !ct.Log.Allowed {
					t.Fatalf("authorize() success must not mark the audit log not-allowed")
				}
				return
			}

			if err == nil {
				t.Fatalf("authorize() = nil, want error %q", tc.wantErr)
			}
			if err.Error() != tc.wantErr {
				t.Fatalf("authorize() = %q, want %q", err, tc.wantErr)
			}
			if tc.wantAllowedFlipped && ct.Log.Allowed {
				t.Fatalf("refusal must mark the audit log not-allowed")
			}
		})
	}
}

// TestAuthorizeHasAccess covers the HasAccess rights level through the
// injected access-resolution seam: the no-target mode, resolution and lookup
// failures, refusal of an unauthorized target, and the context/audit side
// effects of an authorized one.
func TestAuthorizeHasAccess(t *testing.T) {

	user := testUser("alice", "1000", nil)

	// resolvedAccess is what the fake access builder returns: a fully resolved
	// target, the equivalent of a successful DNS + input parse in production.
	resolvedAccess := &models.Access{
		Host: "db1.internal",
		User: "app",
		Port: 2222,
	}

	// fakeAccessBuilder mirrors production resolution: it either resolves to
	// the given access or fails with the given error.
	fakeAccessBuilder := func(ba *models.Access, err error) accessBuilderFunc {
		return func(_ string) (*models.Access, error) {
			return ba, err
		}
	}
	buildOK := fakeAccessBuilder(resolvedAccess, nil)

	t.Run("no access argument is allowed through without grants", func(t *testing.T) {
		ct := testContext(user, nil, map[string]string{})

		err := newAuthorizer(
			withAccessBuilder(func(string) (*models.Access, error) {
				t.Fatal("access builder must not be called without an access argument")
				return nil, nil
			}),
			withAccessChecker(func(*models.User, *models.Access) (*models.Info, error) {
				t.Fatal("access checker must not be called without an access argument")
				return nil, nil
			}),
		).authorize(user, models.HasAccess, ct)

		if err != nil {
			t.Fatalf("authorize() = %q, want success", err)
		}
		if ct.AI != nil || ct.BA != nil {
			t.Fatalf("authorize() without an access argument must leave ct.AI/ct.BA nil")
		}
	})

	t.Run("empty access argument is allowed through without grants", func(t *testing.T) {
		ct := testContext(user, nil, map[string]string{"access": ""})

		err := newAuthorizer().authorize(user, models.HasAccess, ct)

		if err != nil {
			t.Fatalf("authorize() = %q, want success", err)
		}
		if ct.AI != nil || ct.BA != nil {
			t.Fatalf("authorize() with an empty access argument must leave ct.AI/ct.BA nil")
		}
	})

	t.Run("access resolution failure refuses", func(t *testing.T) {
		ct := testContext(user, nil, map[string]string{"access": "app@nosuchhost"})
		resolutionErr := errors.New("unable to resolve host")

		err := newAuthorizer(
			withAccessBuilder(fakeAccessBuilder(nil, resolutionErr)),
		).authorize(user, models.HasAccess, ct)

		if !errors.Is(err, resolutionErr) {
			t.Fatalf("authorize() = %v, want the resolution error", err)
		}
		if ct.Log.Allowed {
			t.Fatalf("a resolution failure must mark the audit log not-allowed")
		}
		if ct.AI != nil || ct.BA != nil {
			t.Fatalf("a refused access must not populate ct.AI/ct.BA")
		}
	})

	t.Run("grants lookup failure refuses", func(t *testing.T) {
		ct := testContext(user, nil, map[string]string{"access": "app@db1.internal:2222"})
		lookupErr := errors.New("unable to read accesses database")

		err := newAuthorizer(
			withAccessBuilder(buildOK),
			withAccessChecker(func(*models.User, *models.Access) (*models.Info, error) {
				return nil, lookupErr
			}),
		).authorize(user, models.HasAccess, ct)

		if !errors.Is(err, lookupErr) {
			t.Fatalf("authorize() = %v, want the lookup error", err)
		}
		if ct.Log.Allowed {
			t.Fatalf("a grants-lookup failure must mark the audit log not-allowed")
		}
	})

	t.Run("unauthorized target refuses and audits the attempt", func(t *testing.T) {
		ct := testContext(user, nil, map[string]string{"access": "app@db1.internal:2222"})

		err := newAuthorizer(
			withAccessBuilder(buildOK),
			withAccessChecker(func(*models.User, *models.Access) (*models.Info, error) {
				return &models.Info{Authorized: false}, nil
			}),
		).authorize(user, models.HasAccess, ct)

		if err == nil || !strings.Contains(err.Error(), "user can't access the host") {
			t.Fatalf("authorize() = %v, want a refusal mentioning the host", err)
		}
		if ct.Log.Allowed {
			t.Fatalf("an unauthorized target must mark the audit log not-allowed")
		}
		// Even a refused attempt records where the user tried to go.
		if ct.Log.HostTo != "db1.internal" || ct.Log.UserTo != "app" || ct.Log.PortTo != "2222" {
			t.Fatalf("refused attempt must still record the target, got host=%q user=%q port=%q",
				ct.Log.HostTo, ct.Log.UserTo, ct.Log.PortTo)
		}
		if ct.AI != nil || ct.BA != nil {
			t.Fatalf("a refused access must not populate ct.AI/ct.BA")
		}
	})

	t.Run("authorized target populates the context and the audit log", func(t *testing.T) {
		ct := testContext(user, nil, map[string]string{"access": "app@db1.internal:2222"})
		grants := &models.Info{
			Authorized:    true,
			KeyFilepathes: []string{"/home/alice/.ssh/id_ed25519"},
		}

		var checkedUser *models.User
		var checkedAccess *models.Access
		err := newAuthorizer(
			withAccessBuilder(buildOK),
			withAccessChecker(func(u *models.User, ba *models.Access) (*models.Info, error) {
				checkedUser, checkedAccess = u, ba
				return grants, nil
			}),
		).authorize(user, models.HasAccess, ct)

		if err != nil {
			t.Fatalf("authorize() = %q, want success", err)
		}
		if checkedUser != user || checkedAccess != resolvedAccess {
			t.Fatalf("the grants lookup must receive the subject user and the resolved access")
		}
		if ct.AI != grants {
			t.Fatalf("ct.AI = %v, want the grants returned by the lookup", ct.AI)
		}
		if ct.BA != resolvedAccess {
			t.Fatalf("ct.BA = %v, want the resolved access", ct.BA)
		}
		if !ct.Log.Allowed {
			t.Fatalf("authorize() success must not mark the audit log not-allowed")
		}
		if ct.Log.HostTo != "db1.internal" || ct.Log.UserTo != "app" || ct.Log.PortTo != "2222" {
			t.Fatalf("authorized attempt must record the target, got host=%q user=%q port=%q",
				ct.Log.HostTo, ct.Log.UserTo, ct.Log.PortTo)
		}
	})
}
