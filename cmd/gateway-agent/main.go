// gateway-agent runs on the data-plane host and exposes the gateway contract
// over a local HTTP endpoint. It is intentionally small: the engine adapter is
// behind internal/gateway and can be replaced after runtime qualification.
package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/gateway"
	"github.com/egressdeck/homelab-proxy-controller/internal/secrets"
)

type agent struct {
	engine  gateway.Engine
	journal gateway.Journal
	token   string
}

func main() {
	engineKind := flag.String("engine", "stock", "engine backend: stock (default), native (patched daemon Unix API), or fake (tests only)")
	nativeSocket := flag.String("native-socket", os.Getenv("GATEWAY_AGENT_NATIVE_SOCKET"), "absolute patched dae daemon Unix socket; requires explicit -engine=native")
	daeExecutable := flag.String("dae-executable", envDefault("GATEWAY_AGENT_DAE_EXECUTABLE", "DAE_EXECUTABLE", "dae"), "operator-owned stock dae executable")
	daeSHA256 := flag.String("dae-sha256", os.Getenv("GATEWAY_AGENT_DAE_SHA256"), "required SHA-256 of the installed dae binary, when supplied")
	daePIDFile := flag.String("dae-pidfile", envDefault("GATEWAY_AGENT_DAE_PIDFILE", "DAE_PIDFILE", "/var/run/dae.pid"), "daemon PID file for process identity readback")
	listen := flag.String("listen", envDefault("GATEWAY_AGENT_LISTEN", "LISTEN_ADDR", "127.0.0.1:9090"), "address for the local agent API")
	tlsCert := flag.String("tls-cert", os.Getenv("GATEWAY_AGENT_TLS_CERT"), "server certificate PEM for mutual TLS")
	tlsKey := flag.String("tls-key", os.Getenv("GATEWAY_AGENT_TLS_KEY"), "server private key PEM")
	clientCA := flag.String("client-ca", os.Getenv("GATEWAY_AGENT_CLIENT_CA"), "trusted controller client certificate CA PEM")
	journalPath := flag.String("journal", envDefault("GATEWAY_AGENT_JOURNAL", "JOURNAL_PATH", "/var/lib/egressdeck/gateway-journal.jsonl"), "durable operation journal path; empty disables file journaling")
	token := flag.String("token", envDefault("GATEWAY_AGENT_TOKEN", "AGENT_TOKEN", ""), "bearer token required for /v1 operations")
	allowUnauthenticated := flag.Bool("dev-allow-unauthenticated", envBool("GATEWAY_AGENT_ALLOW_UNAUTHENTICATED", false), "allow unauthenticated local development mode")
	flag.Parse()
	if *engineKind != "stock" && *engineKind != "fake" && *engineKind != "native" {
		log.Fatal("-engine must be stock, native, or fake")
	}
	if strings.TrimSpace(*token) == "" && !*allowUnauthenticated {
		log.Fatal("gateway-agent requires GATEWAY_AGENT_TOKEN/AGENT_TOKEN or -dev-allow-unauthenticated")
	}
	useTLS := *tlsCert != "" || *tlsKey != "" || *clientCA != ""
	if !useTLS && !loopbackListen(*listen) {
		log.Fatal("non-loopback agent listeners require -tls-cert, -tls-key and -client-ca")
	}
	if *allowUnauthenticated && !loopbackListen(*listen) {
		log.Fatal("unauthenticated development mode requires a literal loopback listener")
	}

	var j gateway.Journal
	if strings.TrimSpace(*journalPath) != "" {
		if *engineKind == "native" {
			j = gateway.NewNativeFileJournal(*journalPath)
		} else {
			j = gateway.NewFileJournal(*journalPath)
		}
	}
	engine := chooseEngine(*engineKind, gateway.StockOptions{Executable: *daeExecutable, ExpectedSHA256: *daeSHA256, PIDFile: *daePIDFile}, j)
	if *engineKind == "native" {
		key, err := secrets.ParseKey(os.Getenv("GATEWAY_AGENT_NATIVE_ENCRYPTION_KEY"))
		if err != nil {
			log.Fatal("native mode requires a base64-encoded 32-byte GATEWAY_AGENT_NATIVE_ENCRYPTION_KEY")
		}
		vault, err := secrets.New(envDefault("GATEWAY_AGENT_NATIVE_ENCRYPTION_KEY_ID", "", "native-primary"), key)
		if err != nil {
			log.Fatal("native encryption key configuration is invalid")
		}
		engine, err = gateway.NewNativeEngine(gateway.NativeOptions{SocketPath: *nativeSocket, Vault: vault}, j)
		if err != nil {
			log.Fatal(err)
		}
	}
	a := &agent{engine: engine, journal: j, token: *token}
	server := &http.Server{Addr: *listen, Handler: a.routes(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	if useTLS {
		var err error
		server.TLSConfig, err = gateway.LoadServerTLS(*tlsCert, *tlsKey, *clientCA)
		if err != nil {
			log.Fatal(err)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	log.Printf("gateway-agent listening on %s with %s backend", *listen, *engineKind)
	var serveErr error
	if useTLS {
		serveErr = server.ListenAndServeTLS("", "")
	} else {
		serveErr = server.ListenAndServe()
	}
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		log.Fatal(serveErr)
	}
}

func chooseEngine(kind string, options gateway.StockOptions, journal gateway.Journal) gateway.Engine {
	if kind == "fake" {
		return gateway.NewFakeEngine(journal)
	}
	return gateway.NewStockEngine(options)
}
func loopbackListen(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func envDefault(primary, secondary, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(primary)); value != "" {
		return value
	}
	if value := strings.TrimSpace(os.Getenv(secondary)); value != "" {
		return value
	}
	return fallback
}
func envBool(name string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func (a *agent) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", a.health)
	mux.HandleFunc("/v1/health", a.auth(a.engineHealth))
	mux.HandleFunc("/v1/capabilities", a.auth(a.capabilities))
	mux.HandleFunc("/v1/inventory", a.auth(a.inventory))
	mux.HandleFunc("/v1/readback", a.auth(a.inventory))
	mux.HandleFunc("/v1/journal", a.auth(a.journalEntries))
	mux.HandleFunc("/v1/mutations/{mutationId}", a.auth(a.mutationStatus))
	mux.HandleFunc("/v1/mutations/{mutationId}/resolve", a.auth(a.resolveMutation))
	mux.HandleFunc("/v1/providers/stage", a.auth(a.stageProvider))
	mux.HandleFunc("/v1/providers/publish", a.auth(a.publishProvider))
	mux.HandleFunc("/v1/providers/{providerId}/publish", a.auth(a.publishProvider))
	mux.HandleFunc("/v1/groups/publish", a.auth(a.publishGroup))
	mux.HandleFunc("/v1/selections/runtime", a.auth(a.runtimeSelection))
	mux.HandleFunc("/v1/selections/persist", a.auth(a.persistSelection))
	mux.HandleFunc("/v1/selections", a.auth(a.selectionRequest))
	mux.HandleFunc("/v1/policy/validate", a.auth(a.validatePolicy))
	mux.HandleFunc("/v1/policy/apply", a.auth(a.applyPolicy))
	mux.HandleFunc("/v1/policies/validate", a.auth(a.validatePolicy))
	mux.HandleFunc("/v1/policies/apply", a.auth(a.applyPolicy))
	mux.HandleFunc("/v1/probes/node", a.auth(a.probeNode))
	mux.HandleFunc("/v1/probes/group", a.auth(a.probeGroup))
	mux.HandleFunc("/v1/probes/node/{nodeId}", a.auth(a.probeNodePath))
	mux.HandleFunc("/v1/probes/group/{groupId}", a.auth(a.probeGroupPath))
	mux.HandleFunc("/v1/connections", a.auth(a.connections))
	mux.HandleFunc("/v1/connections/close", a.auth(a.closeConnections))
	mux.HandleFunc("/v1/counters", a.auth(a.counters))
	mux.HandleFunc("/v1/events", a.auth(a.events))
	return mux
}

type handler func(http.ResponseWriter, *http.Request)

func (a *agent) auth(next handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.token != "" {
			got, present := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !present || len(got) != len(a.token) || subtle.ConstantTimeCompare([]byte(got), []byte(a.token)) != 1 {
				writeError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
		}
		identity, present, err := mutationIdentityFromRequest(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid mutation identity")
			return
		}
		if present {
			r = r.WithContext(gateway.WithMutationIdentity(r.Context(), identity))
			w = &mutationResponseWriter{ResponseWriter: w, identity: identity}
		}
		next(w, r)
	}
}
func (a *agent) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "alive", "observed_at": time.Now().UTC()})
}
func (a *agent) engineHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, 405, "method not allowed")
		return
	}
	if reader, ok := a.engine.(gateway.HealthReader); ok {
		value, err := reader.Health(r.Context())
		writeResult(w, value, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "simulation", "implementation": "egressdeck-fake-engine", "observed_at": time.Now().UTC(), "details": []string{"No real data plane or traffic verification."}})
}
func (a *agent) capabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, 405, "method not allowed")
		return
	}
	value, err := a.engine.Capabilities(r.Context())
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, value)
}
func (a *agent) inventory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, 405, "method not allowed")
		return
	}
	value, err := a.engine.Inventory(r.Context())
	writeResult(w, value, err)
}
func (a *agent) journalEntries(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, 405, "method not allowed")
		return
	}
	if a.journal == nil {
		writeJSON(w, http.StatusOK, []gateway.JournalEntry{})
		return
	}
	value, err := a.journal.Entries(r.Context())
	for i := range value {
		// Native records contain encrypted recovery material, which has no
		// purpose in the public operation journal.
		if value[i].Operation == "native.state" {
			value[i].State = nil
		}
	}
	writeResult(w, value, err)
}

func (a *agent) stageProvider(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "method not allowed")
		return
	}
	req, err := decodeStageRequest(r)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	before, _ := a.engine.Inventory(r.Context())
	id, err := a.engine.StageProvider(r.Context(), req.Revision, req.ExpectedGeneration)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	providerID, revision, contentHash, baseGeneration := req.Revision.ProviderID, req.Revision.Revision, req.Revision.ContentHash, before.Generation
	if staged, ok := a.engine.(gateway.StageInfoProvider); ok {
		if normalized, base, found := staged.StageInfo(id); found {
			providerID, revision, contentHash, baseGeneration = normalized.ProviderID, normalized.Revision, normalized.ContentHash, base
		}
	}
	writeJSON(w, http.StatusCreated, map[string]any{"stage_id": id, "provider_id": providerID, "revision": revision, "content_hash": contentHash, "base_generation": baseGeneration, "status": "staged"})
}

type stageRequest struct {
	Revision           gateway.ProviderRevision
	ExpectedGeneration int64
}

func decodeStageRequest(r *http.Request) (stageRequest, error) {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 8<<20))
	var raw map[string]json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return stageRequest{}, err
	}
	var out stageRequest
	if nested, ok := raw["revision"]; ok && len(nested) > 0 && string(nested) != "null" && nested[0] == '{' {
		var private gateway.ProviderStageRequest
		if err := json.Unmarshal(nested, &private); err != nil {
			return out, err
		}
		out.Revision = private.ProviderRevision()
	} else {
		encoded, err := json.Marshal(raw)
		if err != nil {
			return out, err
		}
		var private gateway.ProviderStageRequest
		if err := json.Unmarshal(encoded, &private); err != nil {
			return out, fmt.Errorf("invalid provider stage request")
		}
		out.Revision = private.ProviderRevision()
	}
	_ = json.Unmarshal(raw["expected_generation"], &out.ExpectedGeneration)
	return out, nil
}
func (a *agent) publishProvider(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "method not allowed")
		return
	}
	var req struct {
		StageID            string `json:"stage_id"`
		ExpectedGeneration int64  `json:"expected_generation"`
	}
	if err := decode(r, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if req.ExpectedGeneration >= 0 {
		observed, readErr := a.engine.Inventory(r.Context())
		if readErr != nil {
			writeEngineError(w, readErr)
			return
		}
		if observed.Generation != req.ExpectedGeneration {
			writeEngineError(w, &gateway.Error{Code: "conflict", Operation: "provider.publish_hot", Detail: "expected generation does not match observed", Cause: gateway.ErrConflict})
			return
		}
	}
	value, err := a.engine.PublishProvider(r.Context(), req.StageID)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "published", "snapshot": value})
}
func (a *agent) runtimeSelection(w http.ResponseWriter, r *http.Request) { a.selection(w, r, false) }
func (a *agent) persistSelection(w http.ResponseWriter, r *http.Request) { a.selection(w, r, true) }
func (a *agent) selectionRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Scope            gateway.SelectionScope `json:"scope"`
		DesiredNodeID    string                 `json:"desired_node_id"`
		ExpectedRevision int64                  `json:"expected_revision"`
		PersistRestart   bool                   `json:"persist_restart"`
	}
	if err := decode(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var value gateway.Selection
	var err error
	if req.PersistRestart {
		value, err = a.engine.PersistSelection(r.Context(), req.Scope, req.DesiredNodeID, req.ExpectedRevision)
	} else {
		value, err = a.engine.SetRuntimeSelection(r.Context(), req.Scope, req.DesiredNodeID, req.ExpectedRevision)
	}
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, value)
}
func (a *agent) selection(w http.ResponseWriter, r *http.Request, persist bool) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		writeError(w, 405, "method not allowed")
		return
	}
	var req struct {
		Scope            gateway.SelectionScope `json:"scope"`
		NodeID           string                 `json:"node_id"`
		ExpectedRevision int64                  `json:"expected_revision"`
	}
	if err := decode(r, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	var value gateway.Selection
	var err error
	if persist {
		value, err = a.engine.PersistSelection(r.Context(), req.Scope, req.NodeID, req.ExpectedRevision)
	} else {
		value, err = a.engine.SetRuntimeSelection(r.Context(), req.Scope, req.NodeID, req.ExpectedRevision)
	}
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, value)
}
func (a *agent) validatePolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "method not allowed")
		return
	}
	var p gateway.Policy
	if err := decode(r, &p); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if err := a.engine.ValidatePolicy(r.Context(), p); err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"valid": true})
}
func (a *agent) applyPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "method not allowed")
		return
	}
	var req struct {
		Policy             gateway.Policy `json:"policy"`
		ExpectedGeneration int64          `json:"expected_generation"`
	}
	if err := decode(r, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	value, err := a.engine.ApplyPolicyGeneration(r.Context(), req.Policy, req.ExpectedGeneration)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, value)
}
func (a *agent) probeNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "method not allowed")
		return
	}
	var req struct {
		NodeID string `json:"node_id"`
	}
	if err := decode(r, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	value, err := a.engine.ProbeNode(r.Context(), req.NodeID)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, value)
}
func (a *agent) probeNodePath(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "method not allowed")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/v1/probes/node/")
	value, err := a.engine.ProbeNode(r.Context(), id)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, value)
}
func (a *agent) probeGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "method not allowed")
		return
	}
	var req struct {
		GroupID string `json:"group_id"`
	}
	if err := decode(r, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	value, err := a.engine.ProbeGroup(r.Context(), req.GroupID)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, value)
}
func (a *agent) probeGroupPath(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "method not allowed")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/v1/probes/group/")
	value, err := a.engine.ProbeGroup(r.Context(), id)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, value)
}
func (a *agent) connections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, 405, "method not allowed")
		return
	}
	value, err := a.engine.ObserveConnections(r.Context())
	writeResult(w, value, err)
}
func (a *agent) closeConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "method not allowed")
		return
	}
	var filter gateway.ConnectionFilter
	if err := decode(r, &filter); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	count, err := a.engine.CloseFiltered(r.Context(), filter)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"closed": count})
}
func (a *agent) counters(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, 405, "method not allowed")
		return
	}
	value, err := a.engine.Counters(r.Context())
	writeResult(w, value, err)
}
func (a *agent) events(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, 405, "method not allowed")
		return
	}
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	value, err := a.engine.ResumeEvents(r.Context(), after)
	writeResult(w, value, err)
}

func decode(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 8<<20))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
func writeResult(w http.ResponseWriter, v any, err error) {
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}
func writeEngineError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	if errors.Is(err, gateway.ErrConflict) {
		status = http.StatusConflict
	} else if errors.Is(err, gateway.ErrBusy) {
		status = http.StatusTooManyRequests
	} else if errors.Is(err, gateway.ErrUnsupported) {
		status = http.StatusNotImplemented
	} else if errors.Is(err, gateway.ErrUnavailable) {
		status = http.StatusServiceUnavailable
	} else if errors.Is(err, gateway.ErrValidation) {
		status = http.StatusUnprocessableEntity
	} else if errors.Is(err, gateway.ErrStageNotFound) {
		status = http.StatusNotFound
	} else if errors.Is(err, gateway.ErrInvalidRevision) || errors.Is(err, gateway.ErrSelection) {
		status = http.StatusBadRequest
	}
	if writeMutationRejection(w, status, err) {
		return
	}
	var typed *gateway.Error
	if errors.As(err, &typed) {
		writeJSON(w, status, map[string]any{"error": typed})
		return
	}
	writeError(w, status, err.Error())
}
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Ensure local builds fail early if an agent is accidentally wired to a nil
// implementation while adding a new endpoint.
var _ gateway.Engine = (*gateway.StockEngine)(nil)
