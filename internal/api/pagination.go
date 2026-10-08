package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	collectionDefaultLimit     = 100
	collectionMaxLimit         = 500
	collectionMaxPageBytes     = 4 << 20
	collectionMaxSnapshotBytes = 64 << 20
	collectionMaxItems         = 100000
	collectionCursorTTL        = 15 * time.Minute
)

// Collection cursors refer to the stable public resource snapshot. A concurrent
// configuration change causes an explicit restart (409), never skipped rows.
// Live gateway and firewall observations may refresh between pages.
// They hold hashes only, are authenticated, and expire without retaining copies.
type collectionCursor struct {
	Version  int    `json:"v"`
	Route    string `json:"r"`
	Snapshot string `json:"s"`
	After    string `json:"a"`
	Limit    int    `json:"l"`
	Issued   int64  `json:"t"`
}
type collectionRequest struct {
	limit      int
	route      string
	cursor     *collectionCursor
	signingKey []byte
}
type collectionContextKey struct{}

func isCollectionPattern(pattern string) bool {
	switch pattern {
	case "/api/v1/devices", "/api/v1/device-groups", "/api/v1/gateways",
		"/api/v1/providers", "/api/v1/nodes", "/api/v1/outbound-groups",
		"/api/v1/policies", "/api/v1/rule-sets", "/api/v1/firewall-bindings",
		"/api/v1/operations", "/api/v1/audit-events", "/api/v1/providers/{id}/revisions":
		return true
	default:
		return false
	}
}

func newCollectionPagination() func(string, http.HandlerFunc) http.HandlerFunc {
	signingKey := make([]byte, 32)
	if _, err := rand.Read(signingKey); err != nil {
		panic("pagination signing key unavailable")
	}
	return func(pattern string, next http.HandlerFunc) http.HandlerFunc {
		if !isCollectionPattern(pattern) {
			return next
		}
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				next(w, r)
				return
			}
			request, status, message := parseCollectionRequest(r, signingKey)
			if status != 0 {
				code := "invalid_cursor"
				if status == http.StatusConflict {
					code = "stale_cursor"
				}
				writeError(w, status, code, message)
				return
			}
			next(w, r.WithContext(context.WithValue(r.Context(), collectionContextKey{}, request)))
		}
	}
}

func parseCollectionRequest(r *http.Request, signingKey []byte) (collectionRequest, int, string) {
	request := collectionRequest{limit: collectionDefaultLimit, signingKey: signingKey}
	if len(r.URL.RawQuery) > 4096 {
		return request, 400, "Collection query exceeds 4096 bytes."
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return request, 400, "Collection query encoding is invalid."
	}
	for _, field := range []string{"limit", "cursor"} {
		if len(query[field]) > 1 {
			return request, 400, "Collection limit and cursor must each occur once."
		}
	}
	if raw, ok := query["limit"]; ok {
		limit, err := strconv.Atoi(raw[0])
		if err != nil || limit < 1 || limit > collectionMaxLimit {
			return request, 400, "Collection limit must be between 1 and 500."
		}
		request.limit = limit
	}
	query.Del("limit")
	query.Del("cursor")
	request.route = collectionHash([]byte(r.URL.EscapedPath() + "?" + query.Encode()))
	raw, hasCursor := r.URL.Query()["cursor"]
	if !hasCursor {
		return request, 0, ""
	}
	if raw[0] == "" || len(raw[0]) > 2048 {
		return request, 400, "Collection cursor is invalid."
	}
	parts := strings.Split(raw[0], ".")
	if len(parts) != 2 {
		return request, 400, "Collection cursor is invalid."
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return request, 400, "Collection cursor is invalid."
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	mac := hmac.New(sha256.New, signingKey)
	mac.Write(payload)
	if err != nil || !hmac.Equal(signature, mac.Sum(nil)) {
		return request, 400, "Collection cursor is invalid or belongs to an earlier controller process."
	}
	var cursor collectionCursor
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&cursor) != nil || cursor.Version != 1 || cursor.Route != request.route || cursor.Limit != request.limit || len(cursor.Snapshot) != 64 || len(cursor.After) != 64 {
		return request, 400, "Collection cursor does not match this route, query, or limit."
	}
	age := time.Now().Unix() - cursor.Issued
	if age < 0 || age > int64(collectionCursorTTL/time.Second) {
		return request, 409, "Collection cursor expired. Restart from the first page."
	}
	request.cursor = &cursor
	return request, 0, ""
}

func collectionHash(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
func encodeCollectionCursor(cursor collectionCursor, signingKey []byte) string {
	payload, _ := json.Marshal(cursor)
	mac := hmac.New(sha256.New, signingKey)
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Observation fields are deliberately excluded for live projections: time or
// health changes do not change membership/configuration or invalidate paging.
func collectionSnapshotItem(path string, data json.RawMessage) []byte {
	switch path {
	case "/api/v1/gateways":
		var value map[string]json.RawMessage
		_ = json.Unmarshal(data, &value)
		stable := map[string]json.RawMessage{}
		for _, key := range []string{"id", "name", "endpoint", "adapter", "revision", "created_at", "updated_at"} {
			stable[key] = value[key]
		}
		encoded, _ := json.Marshal(stable)
		return encoded
	case "/api/v1/firewall-bindings":
		var value map[string]json.RawMessage
		_ = json.Unmarshal(data, &value)
		stable := map[string]json.RawMessage{}
		for _, key := range []string{"id", "gateway_id", "alias", "alias_uuid", "address_family", "interface_scope", "rule_ids", "desired_count"} {
			stable[key] = value[key]
		}
		encoded, _ := json.Marshal(stable)
		return encoded
	default:
		return data
	}
}

type collectionItem struct {
	key  string
	data json.RawMessage
}

// writeCollection leaves every public item unchanged, including revision detail
// and adapter metadata. Bounds apply to HTTP page bytes and snapshot encoding;
// storage List methods still materialize their data and are not SQL pagination.
func writeCollection[T any](w http.ResponseWriter, r *http.Request, values []T, extra map[string]any) {
	request, ok := r.Context().Value(collectionContextKey{}).(collectionRequest)
	if !ok {
		writeError(w, 500, "internal_error", "Collection pagination is not configured.")
		return
	}
	if len(values) > collectionMaxItems {
		writeError(w, 503, "collection_capacity", "Collection exceeds the 100000 item scan limit.")
		return
	}
	items := make([]collectionItem, 0, len(values))
	snapshotBytes := 0
	for _, value := range values {
		if r.Context().Err() != nil {
			return
		}
		data, err := json.Marshal(value)
		if err != nil {
			writeError(w, 500, "internal_error", "Collection item could not be encoded.")
			return
		}
		snapshotBytes += len(data)
		if snapshotBytes > collectionMaxSnapshotBytes {
			writeError(w, 503, "collection_capacity", "Collection exceeds the 64 MiB public snapshot scan limit.")
			return
		}
		var identity struct {
			ID     string `json:"id"`
			Number int64  `json:"number"`
		}
		if json.Unmarshal(data, &identity) != nil || (identity.ID == "" && identity.Number <= 0) {
			writeError(w, 500, "internal_error", "Collection item has no stable identity.")
			return
		}
		key := identity.ID
		if key == "" {
			key = fmt.Sprintf("%020d", identity.Number)
		}
		items = append(items, collectionItem{key: key, data: data})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].key < items[j].key })
	digest := sha256.New()
	for i, item := range items {
		if i > 0 && items[i-1].key == item.key {
			writeError(w, 500, "internal_error", "Collection contains duplicate stable identities.")
			return
		}
		digest.Write(collectionSnapshotItem(r.URL.Path, item.data))
		digest.Write([]byte{'\n'})
	}
	snapshot := hex.EncodeToString(digest.Sum(nil))
	start := 0
	issued := time.Now().Unix()
	if cursor := request.cursor; cursor != nil {
		if cursor.Snapshot != snapshot {
			writeError(w, 409, "stale_cursor", "Collection changed. Restart from the first page.")
			return
		}
		found := false
		for i, item := range items {
			if collectionHash([]byte(item.key)) == cursor.After {
				start, found = i+1, true
				break
			}
		}
		if !found {
			writeError(w, 400, "invalid_cursor", "Collection cursor position is invalid.")
			return
		}
		issued = cursor.Issued
	}
	end, pageBytes := start, 0
	for end < len(items) && end-start < request.limit {
		// Reserve space for envelope, metadata and cursor.
		size := len(items[end].data) + 1
		if pageBytes+size > collectionMaxPageBytes-4096 {
			if end == start {
				writeError(w, 413, "collection_item_too_large", "A collection item exceeds the 4 MiB page limit.")
				return
			}
			break
		}
		pageBytes += size
		end++
	}
	page := make([]json.RawMessage, 0, end-start)
	for _, item := range items[start:end] {
		page = append(page, item.data)
	}
	body := make(map[string]any, len(extra)+4)
	for key, value := range extra {
		body[key] = value
	}
	body["items"], body["limit"], body["total"] = page, request.limit, len(items)
	if end < len(items) {
		body["next_cursor"] = encodeCollectionCursor(collectionCursor{Version: 1, Route: request.route, Snapshot: snapshot, After: collectionHash([]byte(items[end-1].key)), Limit: request.limit, Issued: issued}, request.signingKey)
	}
	encoded, err := json.Marshal(body)
	if err != nil || len(encoded) > collectionMaxPageBytes {
		writeError(w, 500, "internal_error", "Collection page exceeds its encoding limit.")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(encoded)
}
