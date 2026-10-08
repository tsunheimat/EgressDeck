package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGatewayProbeAndInventoryPlanRoles(t *testing.T) {
	for _, tc := range []struct {
		method, path string
		role         Role
	}{
		{"POST", "/api/v1/gateways/gateway-1/probes/nodes/node-1", RoleOperator},
		{"POST", "/api/v1/gateways/gateway-1/probes/groups/group-1", RoleOperator},
		{"GET", "/api/v1/gateways/gateway-1/connections", RoleViewer},
		{"GET", "/api/v1/gateways/gateway-1/counters", RoleViewer},
		{"POST", "/api/v1/deployments/plan", RoleOperator},
		{"GET", "/api/v1/deployments/plans/0123456789abcdef", RoleViewer},
		{"PUT", "/api/v1/deployments/plan", RoleAdmin},
		{"POST", "/api/v1/deployments/plan/extra", RoleAdmin},
		{"POST", "/api/v1/deployments%2fplan", RoleAdmin},
		{"PUT", "/api/v1/gateways/gateway-1/probes/nodes/node-1", RoleAdmin},
		{"DELETE", "/api/v1/gateways/gateway-1/probes/groups/group-1", RoleAdmin},
		{"POST", "/api/v1/gateways/gateway-1/probes/nodes", RoleAdmin},
		{"POST", "/api/v1/gateways/gateway-1/probes/nodes/", RoleAdmin},
		{"POST", "/api/v1/gateways//probes/nodes/node-1", RoleAdmin},
		{"POST", "/api/v1/gateways/gateway-1/probes/nodes/node-1/extra", RoleAdmin},
		{"POST", "/api/v1/gateways/gateway-1/probes/node/node-1", RoleAdmin},
		{"POST", "/api/v1/gateways/gateway-1/probes/connections/node-1", RoleAdmin},
		{"POST", "/api/v1/gateways/gateway-1/connections/close", RoleAdmin},
		{"POST", "/api/v1/gateways/gateway-1%2fprobes%2fnodes%2fnode-1", RoleAdmin},
		{"POST", "/api/v1/gateways/gateway-1/probes%2fnodes/node-1", RoleAdmin},
		// A slash encoded within an ID remains a single ServeMux segment.
		{"POST", "/api/v1/gateways/gateway%2f1/probes/nodes/node%2f1", RoleOperator},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			if got := RequiredRole(httptest.NewRequest(tc.method, tc.path, nil)); got != tc.role {
				t.Fatalf("required role=%q, want %q", got, tc.role)
			}
		})
	}
}

func TestProbeAndPlanAuthorizationEnforcesRolesAndCSRF(t *testing.T) {
	sessions := NewSessionManager([]byte("01234567890123456789012345678901"))
	mw := NewMiddleware(sessions)
	for _, path := range []string{"/api/v1/gateways/gateway-1/probes/nodes/node-1", "/api/v1/gateways/gateway-1/probes/groups/group-1", "/api/v1/deployments/plan"} {
		for _, tc := range []struct {
			role Role
			csrf bool
			want int
		}{
			{RoleViewer, true, http.StatusForbidden},
			{RoleOperator, false, http.StatusForbidden},
			{RoleOperator, true, http.StatusNoContent},
			{RoleAdmin, true, http.StatusNoContent},
		} {
			t.Run(string(tc.role)+" "+path+map[bool]string{true: " csrf", false: " no csrf"}[tc.csrf], func(t *testing.T) {
				session, err := sessions.Issue("alice", tc.role)
				if err != nil {
					t.Fatal(err)
				}
				login := httptest.NewRecorder()
				if err := sessions.SetSession(login, session); err != nil {
					t.Fatal(err)
				}
				req := httptest.NewRequest(http.MethodPost, path, nil)
				for _, cookie := range login.Result().Cookies() {
					req.AddCookie(cookie)
				}
				if tc.csrf {
					req.Header.Set("X-CSRF-Token", session.CSRFToken)
				}
				called := false
				next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					called = true
					principal, ok := SessionFromContext(r.Context())
					if !ok || principal.Subject != "alice" {
						t.Error("authenticated identity missing from request")
					}
					w.WriteHeader(http.StatusNoContent)
				})
				rec := httptest.NewRecorder()
				mw.Require(RequiredRole(req))(mw.CSRF(next)).ServeHTTP(rec, req)
				if rec.Code != tc.want || called != (tc.want == http.StatusNoContent) {
					t.Fatalf("status=%d called=%v, want status=%d", rec.Code, called, tc.want)
				}
			})
		}
	}
}
