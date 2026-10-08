// Package auth contains the controller's authentication and authorization
// primitives.  It intentionally has no dependency on the API or persistence
// packages so that every HTTP entry point can apply the same checks.
package auth

import "strings"

// Role is an application role. Roles are ordered: an administrator has all
// operator and viewer permissions, and an operator has all viewer permissions.
type Role string

const (
	RoleViewer   Role = "viewer"
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
)

func (r Role) String() string { return string(r) }

// ParseRole accepts the canonical role names and the long administrator name
// commonly used by identity providers.
func ParseRole(raw string) (Role, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "viewer":
		return RoleViewer, true
	case "operator":
		return RoleOperator, true
	case "admin", "administrator":
		return RoleAdmin, true
	default:
		return "", false
	}
}

func (r Role) level() int {
	switch r {
	case RoleViewer:
		return 1
	case RoleOperator:
		return 2
	case RoleAdmin:
		return 3
	default:
		return 0
	}
}

// Allows reports whether r grants the required permission.
func (r Role) Allows(required Role) bool {
	return r.level() >= required.level() && required.level() != 0
}

// HasRole reports whether any role in roles grants required. Unknown roles do
// not grant permissions, even when a caller accidentally sends a malformed
// identity-provider claim.
func HasRole(roles []Role, required Role) bool {
	for _, role := range roles {
		if role.Allows(required) {
			return true
		}
	}
	return false
}

// NormalizeRoles removes unknown and duplicate roles while preserving the
// strongest role first. This makes authorization deterministic and keeps
// audit/session payloads compact.
func NormalizeRoles(roles []Role) []Role {
	seen := make(map[Role]struct{}, len(roles))
	var out []Role
	for _, role := range roles {
		parsed, ok := ParseRole(string(role))
		if !ok {
			continue
		}
		if _, exists := seen[parsed]; exists {
			continue
		}
		seen[parsed] = struct{}{}
		out = append(out, parsed)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].level() > out[j-1].level(); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// HighestRole returns the strongest known role or an empty role when none is
// present.
func HighestRole(roles []Role) Role {
	var highest Role
	for _, role := range roles {
		if role.level() > highest.level() {
			highest = role
		}
	}
	return highest
}
