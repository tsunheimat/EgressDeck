package auth

import (
	"net/http"
	"net/url"
	"strings"
)

// RequiredRole defines controller API authorization for production and test
// servers. Mutations require administrator access unless this exact operation
// is an approved runtime or deployment action. New endpoints require admin
// until their operation has an explicit role assignment here.
func RequiredRole(r *http.Request) Role {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return RoleViewer
	}
	// ServeMux splits the escaped path before unescaping each segment. Match
	// that same boundary so an encoded slash inside an object ID cannot turn
	// an administrator CRUD request into an operator action here.
	parts := strings.Split(strings.TrimPrefix(r.URL.EscapedPath(), "/api/v1/"), "/")
	for i, part := range parts {
		decoded, err := url.PathUnescape(part)
		if err != nil {
			return RoleAdmin
		}
		parts[i] = decoded
	}
	if len(parts) == 3 && parts[0] == "outbound-groups" && parts[1] != "" && parts[2] == "selection" && (r.Method == http.MethodPut || r.Method == http.MethodPost) {
		return RoleOperator
	}
	if r.Method == http.MethodPost {
		if len(parts) == 5 && parts[0] == "gateways" && parts[1] != "" && parts[2] == "probes" && (parts[3] == "nodes" || parts[3] == "groups") && parts[4] != "" {
			return RoleOperator
		}
		if len(parts) == 1 && parts[0] == "operations" {
			return RoleOperator
		}
		if len(parts) == 5 && parts[0] == "providers" && parts[1] != "" && parts[2] == "revisions" && parts[3] != "" && parts[4] == "apply" {
			return RoleOperator
		}
		if len(parts) == 2 && ((parts[0] == "deployments" && (parts[1] == "preview" || parts[1] == "plan")) || (parts[0] == "policies" && parts[1] == "explain") || (parts[0] == "probes" && (parts[1] == "node" || parts[1] == "group"))) {
			return RoleOperator
		}
	}
	return RoleAdmin
}
