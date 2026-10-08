package main

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/egressdeck/homelab-proxy-controller/internal/gateway"
)

var mutationHeaders = []string{
	"X-EgressDeck-Mutation-ID",
	"X-EgressDeck-Mutation-Hash",
	"X-EgressDeck-Mutation-Target-Kind",
	"X-EgressDeck-Mutation-Target-ID",
	"X-EgressDeck-Mutation-Fence",
}

func mutationIdentityFromRequest(r *http.Request) (gateway.MutationIdentity, bool, error) {
	values := make([]string, len(mutationHeaders))
	present := false
	for i, key := range mutationHeaders {
		headerValues := r.Header.Values(key)
		if len(headerValues) != 0 {
			present = true
		}
		if len(headerValues) > 1 {
			return gateway.MutationIdentity{}, true, errors.New("duplicate mutation identity header")
		}
		if len(headerValues) == 1 {
			values[i] = headerValues[0]
		}
	}
	if !present {
		return gateway.MutationIdentity{}, false, nil
	}
	fence, err := strconv.ParseUint(values[4], 10, 64)
	if err != nil || strconv.FormatUint(fence, 10) != values[4] {
		return gateway.MutationIdentity{}, true, errors.New("invalid mutation fence")
	}
	identity := gateway.MutationIdentity{ID: values[0], RequestHash: values[1], TargetKind: values[2], TargetID: values[3], FenceToken: fence}
	return identity, true, identity.Validate()
}

func mutationIdentityForRoute(w http.ResponseWriter, r *http.Request) (gateway.MutationIdentity, bool) {
	identity, present := gateway.MutationIdentityFromContext(r.Context())
	if !present || r.PathValue("mutationId") != identity.ID {
		writeError(w, http.StatusBadRequest, "mutation route and identity must match")
		return gateway.MutationIdentity{}, false
	}
	return identity, true
}

func (a *agent) mutationStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	identity, ok := mutationIdentityForRoute(w, r)
	if !ok {
		return
	}
	reader, ok := a.engine.(gateway.MutationStatusReader)
	if !ok {
		writeEngineError(w, &gateway.Error{Code: "unsupported", Operation: "mutation.status", Cause: gateway.ErrUnsupported})
		return
	}
	result, err := reader.MutationStatus(r.Context(), identity)
	writeMutationReceipt(w, identity, result, err)
}

func (a *agent) resolveMutation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	identity, ok := mutationIdentityForRoute(w, r)
	if !ok {
		return
	}
	resolver, ok := a.engine.(gateway.MutationResolver)
	if !ok {
		writeEngineError(w, &gateway.Error{Code: "unsupported", Operation: "mutation.resolve", Cause: gateway.ErrUnsupported})
		return
	}
	result, err := resolver.ResolveMutation(r.Context(), identity)
	writeMutationReceipt(w, identity, result, err)
}

func writeMutationReceipt(w http.ResponseWriter, identity gateway.MutationIdentity, result gateway.MutationReceipt, err error) {
	if err != nil {
		writeEngineError(w, err)
		return
	}
	if err := result.ValidateFor(identity); err != nil {
		writeError(w, http.StatusInternalServerError, "invalid mutation receipt")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// An explicit preflight rejection is distinct from a generic conflict. Bind
// its proof to the complete authenticated identity before forwarding it.
type mutationResponseWriter struct {
	http.ResponseWriter
	identity gateway.MutationIdentity
}

func (w *mutationResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func writeMutationRejection(w http.ResponseWriter, status int, err error) bool {
	writer, ok := w.(*mutationResponseWriter)
	if !ok || !gateway.IsDefiniteRejection(err) {
		return false
	}
	var rejection *gateway.RequestRejected
	if !errors.As(err, &rejection) {
		return false
	}
	writeJSON(w, status, map[string]any{
		"error":                    gateway.Error{Code: "request_rejected", Detail: "gateway rejected this mutation before execution"},
		"rejected_before_mutation": true,
		"mutation_identity":        writer.identity,
	})
	return true
}
