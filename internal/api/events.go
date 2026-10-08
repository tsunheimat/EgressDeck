package api

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	defaultEventLimit = 100
	maxEventLimit     = 500
	eventRetention    = 5000
)

// ManagementEvent is a safe projection of a management record. Polling captures
// the latest source snapshot, rather than promising every intermediate state
// transition. The persisted feed retains snapshots already returned to clients.
type ManagementEvent struct {
	ID           string    `json:"id"`
	Sequence     uint64    `json:"sequence"`
	Type         string    `json:"type"`
	ResourceType string    `json:"resource_type"`
	ResourceID   string    `json:"resource_id"`
	Action       string    `json:"action"`
	Status       string    `json:"status"`
	OperationID  string    `json:"operation_id,omitempty"`
	OccurredAt   time.Time `json:"occurred_at"`
}

type eventPage struct {
	Items      []ManagementEvent `json:"items"`
	NextCursor string            `json:"next_cursor"`
	HasMore    bool              `json:"has_more"`
	Resumable  bool              `json:"resumable"`
	Durable    bool              `json:"durable"`
}

func (s *Server) eventsFeed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	query := r.URL.Query()
	if len(query["limit"]) > 1 || len(query["cursor"]) > 1 {
		writeError(w, 400, "invalid_query", "cursor and limit must each appear at most once")
		return
	}
	limit := defaultEventLimit
	if raw := query.Get("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > maxEventLimit {
			writeError(w, 400, "invalid_limit", "limit must be between 1 and 500")
			return
		}
		limit = value
	}
	rawCursor := query.Get("cursor")
	stream := ""
	after := uint64(0)
	if rawCursor != "" {
		var err error
		stream, after, err = decodeEventCursor(rawCursor)
		if err != nil {
			writeError(w, 400, "invalid_cursor", "cursor is invalid")
			return
		}
	}
	state, durable, err := s.servicesOrDefault().projectEvents(r.Context())
	if err != nil {
		writeError(w, 503, "events_unavailable", "management event storage is unavailable")
		return
	}
	if rawCursor != "" {
		if stream != state.Stream {
			writeError(w, 410, "cursor_stream_changed", "event stream was replaced; reload current state before resuming")
			return
		}
		if after > state.Sequence {
			writeError(w, 400, "invalid_cursor", "cursor is ahead of the event stream")
			return
		}
		if len(state.Events) > 0 && after < state.Events[0].Sequence-1 {
			writeError(w, 410, "cursor_expired", "cursor is older than retained history; reload current state before resuming")
			return
		}
	}
	page := eventPage{Items: []ManagementEvent{}, Resumable: true, Durable: durable}
	last := after
	for _, event := range state.Events {
		if event.Sequence <= after {
			continue
		}
		if len(page.Items) == limit {
			page.HasMore = true
			break
		}
		page.Items = append(page.Items, event)
		last = event.Sequence
	}
	if len(page.Items) == 0 {
		last = state.Sequence
	}
	page.NextCursor = encodeEventCursor(state.Stream, last)
	writeJSON(w, http.StatusOK, page)
}

func encodeEventCursor(stream string, sequence uint64) string {
	return base64.RawURLEncoding.EncodeToString([]byte("v1:" + stream + ":" + strconv.FormatUint(sequence, 10)))
}
func decodeEventCursor(raw string) (string, uint64, error) {
	if len(raw) > 256 {
		return "", 0, errors.New("cursor too long")
	}
	value, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	parts := strings.Split(string(value), ":")
	if err != nil || len(parts) != 3 || parts[0] != "v1" || !eventIdentifierPattern.MatchString(parts[1]) {
		return "", 0, errors.New("invalid cursor")
	}
	sequence, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil || strconv.FormatUint(sequence, 10) != parts[2] {
		return "", 0, errors.New("invalid sequence")
	}
	return parts[1], sequence, nil
}
