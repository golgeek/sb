package commands

import (
	"fmt"

	"github.com/golgeek/sb/internal/models"
)

// NoMatchingAccessError reports that the user holds no grant matching the
// requested target. It is a distinct type so the front-end can tell "the
// access path matched nothing" apart from every other failure and offer a
// command suggestion for what was probably a mistyped command name, without
// ever weakening the refusal itself.
type NoMatchingAccessError struct {
	// Target is the short form of the access the user asked for.
	Target string
}

// Error returns the historical refusal message unchanged.
func (e *NoMatchingAccessError) Error() string {
	return fmt.Sprintf("user can't access the host %s", e.Target)
}

// accessBuilderFunc resolves a user-supplied access string ("user@host[:port]"
// or a bare alias) into a models.Access. The production implementation is
// models.BuildSBAccessFromUserInput, which performs a DNS resolution of the
// host as part of the build; tests inject a hermetic replacement.
type accessBuilderFunc func(input string) (*models.Access, error)

// accessCheckerFunc reports whether the given user is granted the candidate
// access, returning the matching grants on success. The production
// implementation is (*models.User).HasAccess, which reads the per-user and
// per-group accesses databases; tests inject a hermetic replacement.
type accessCheckerFunc func(user *models.User, ba *models.Access) (*models.Info, error)

// authorizer is the authorization gate of the command dispatcher: it decides
// whether a user may run a command registered at a given rights level. It is
// deliberately a small struct holding only the two effectful dependencies of
// the HasAccess level (DNS resolution and accesses-database lookups), injected
// through newAuthorizer so the security-critical decision logic can be unit
// tested hermetically.
type authorizer struct {
	buildAccess accessBuilderFunc
	hasAccess   accessCheckerFunc
}

// authorizerOption customizes an authorizer built by newAuthorizer.
type authorizerOption func(*authorizer)

// withAccessBuilder overrides how the "access" argument is resolved into a
// models.Access. Intended for tests, which must not perform DNS lookups.
func withAccessBuilder(f accessBuilderFunc) authorizerOption {
	return func(a *authorizer) {
		a.buildAccess = f
	}
}

// withAccessChecker overrides how a user's grant for an access is looked up.
// Intended for tests, which must not touch the accesses databases.
func withAccessChecker(f accessCheckerFunc) authorizerOption {
	return func(a *authorizer) {
		a.hasAccess = f
	}
}

// newAuthorizer returns an authorizer wired with the production dependencies
// (DNS-resolving access builder, database-backed access lookup), then applies
// the given options. Call sites on the dispatch path use newAuthorizer() as-is;
// tests pass options to substitute hermetic fakes.
func newAuthorizer(opts ...authorizerOption) *authorizer {
	a := &authorizer{
		buildAccess: models.BuildSBAccessFromUserInput,
		hasAccess: func(user *models.User, ba *models.Access) (*models.Info, error) {
			return user.HasAccess(ba)
		},
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// authorize enforces a command's rights level for a user and is the single
// authorization gate of the dispatcher: every command execution must pass
// through it exactly once, before the command's own Checks/Execute run.
//
// Parameters:
//   - user: the authorization subject (the calling sb account). It is the
//     same object as ct.User on the dispatch path; it is passed explicitly so
//     the subject of the decision is visible at the call site.
//   - rights: the rights level the command was registered with.
//   - ct: the command context. authorize reads ct.FormattedArguments["access"]
//     and ct.Group, writes the audit trail through ct.Log, and on a successful
//     HasAccess check populates ct.AI (matching grants) and ct.BA (resolved
//     target) for the command to consume.
//
// It returns nil when the user is allowed to run the command and a descriptive
// error otherwise. Every refusal — and any internal failure on the HasAccess
// path — leaves the audit log marked not-allowed; audit-write failures are
// reported to stderr without changing the decision. The decision logic fails
// closed: a rights level this function does not recognize is refused rather
// than allowed, and a group-scoped level with no resolved group is refused
// rather than dereferencing a nil group.
func (a *authorizer) authorize(user *models.User, rights models.Right, ct *Context) error {

	switch rights {

	case models.Public:
		// Public commands are available to every sb account.
		return nil

	case models.Private:
		// Private commands must be run by root.
		if user.User.Username != "root" {
			logAuditWarn(ct.Log.SetAllowed(false))
			return fmt.Errorf("only root user can execute this command on sb")
		}
		return nil

	case models.HasAccess:
		return a.authorizeAccess(user, ct)

	case models.GroupMember:
		grp, err := requireGroup(ct)
		if err != nil {
			return err
		}
		if !user.IsMemberOfGroup(grp.Name) {
			logAuditWarn(ct.Log.SetAllowed(false))
			return fmt.Errorf("user is not a member of the group")
		}
		return nil

	case models.GroupACLKeeper:
		grp, err := requireGroup(ct)
		if err != nil {
			return err
		}
		if !user.IsACLKeeperOfGroup(grp.Name) {
			logAuditWarn(ct.Log.SetAllowed(false))
			return fmt.Errorf("user is not an ACL keeper of the group")
		}
		return nil

	case models.GroupGateKeeper:
		grp, err := requireGroup(ct)
		if err != nil {
			return err
		}
		if !user.IsGateKeeperOfGroup(grp.Name) {
			logAuditWarn(ct.Log.SetAllowed(false))
			return fmt.Errorf("user is not a gate keeper of the group")
		}
		return nil

	case models.GroupOwner:
		// Owners of the special "owners" super-group administer every group,
		// so they pass group-owner checks for any group.
		grp, err := requireGroup(ct)
		if err != nil {
			return err
		}
		if !user.IsOwnerOfGroup(grp.Name) && !user.IsOwnerOfGroup("owners") {
			logAuditWarn(ct.Log.SetAllowed(false))
			return fmt.Errorf("user is not an owner of the group")
		}
		return nil

	case models.SBOwner:
		// sb-wide administration is reserved to owners of the "owners"
		// super-group, or to root itself (UID 0).
		if !user.IsOwnerOfGroup("owners") && user.User.Uid != "0" {
			logAuditWarn(ct.Log.SetAllowed(false))
			return fmt.Errorf("user is not a sb owner")
		}
		return nil

	default:
		// Fail closed: a rights level we do not recognize (e.g. a new level
		// added to models without a matching case here) must never grant
		// access by falling through the switch.
		logAuditWarn(ct.Log.SetAllowed(false))
		return fmt.Errorf("unrecognized rights level %d: refusing execution", rights)
	}
}

// authorizeAccess enforces the HasAccess rights level: when an "access"
// argument is present, it resolves it and checks the user's grants, recording
// the requested target in the audit log either way.
//
// A missing or empty "access" argument is allowed through with ct.AI and ct.BA
// left nil: commands at this level have modes that target no host (for example
// scp's --get-script), and their Execute handles the nil case. When the
// argument is present, a resolution failure, a grants-lookup failure, or an
// unauthorized target each refuse the command and mark the audit log
// not-allowed; on success the matching grants (ct.AI) and the resolved target
// (ct.BA) are attached to the context for the command to consume.
func (a *authorizer) authorizeAccess(user *models.User, ct *Context) error {

	host, ok := ct.FormattedArguments["access"]
	if !ok || host == "" {
		return nil
	}

	ba, err := a.buildAccess(host)
	if err != nil {
		logAuditWarn(ct.Log.SetAllowed(false))
		return err
	}

	// Record the requested target in the audit log before deciding, so even
	// refused attempts keep a trace of where the user tried to go.
	logAuditWarn(ct.Log.SetTargetAccess(ba))

	ai, err := a.hasAccess(user, ba)
	if err != nil {
		logAuditWarn(ct.Log.SetAllowed(false))
		return err
	}
	if !ai.Authorized {
		logAuditWarn(ct.Log.SetAllowed(false))
		return &NoMatchingAccessError{Target: ba.ShortString()}
	}

	ct.AI = ai
	ct.BA = ba
	return nil
}

// requireGroup returns the group resolved from the command's --group argument,
// or refuses the command (marking the audit log not-allowed) when no group is
// attached to the context. Group-scoped rights levels are meaningless without
// a group, and reaching one without a resolved group must fail closed instead
// of dereferencing nil — the situation is reachable if a group-scoped command
// ever registers its "group" argument as optional.
func requireGroup(ct *Context) (*models.Group, error) {
	if ct.Group == nil {
		logAuditWarn(ct.Log.SetAllowed(false))
		return nil, fmt.Errorf("this command requires a group, but none was provided")
	}
	return ct.Group, nil
}
