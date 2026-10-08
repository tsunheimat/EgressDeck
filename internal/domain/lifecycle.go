package domain

import "time"

// ProviderRevision is immutable after staging. ContentHash binds the parsed
// inventory to the bytes that were fetched, while State tracks staged/active
// and failed revisions independently from the provider record.
type ProviderRevision struct {
	ProviderID  string    `json:"provider_id"`
	Revision    int64     `json:"revision"`
	ContentHash string    `json:"content_hash"`
	NodeIDs     []string  `json:"node_ids"`
	State       string    `json:"state"`
	ParseReport string    `json:"parse_report,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

type NodeRevision struct {
	NodeID         string    `json:"node_id"`
	Revision       int64     `json:"revision"`
	ConnectionHash string    `json:"connection_hash"`
	Protocol       string    `json:"protocol"`
	CreatedAt      time.Time `json:"created_at"`
}

type OutboundSelection struct {
	OutboundGroupID string    `json:"outbound_group_id"`
	GatewayID       string    `json:"gateway_id"`
	Transport       string    `json:"transport"`
	DesiredNodeID   string    `json:"desired_node_id"`
	ObservedNodeID  string    `json:"observed_node_id"`
	Revision        int64     `json:"revision"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type FirewallBinding struct {
	ID           string        `json:"id"`
	GatewayID    string        `json:"gateway_id"`
	Family       AddressFamily `json:"family"`
	Interface    string        `json:"interface"`
	Alias        string        `json:"alias"`
	RuleIDs      []string      `json:"rule_ids"`
	ObservedHash string        `json:"observed_hash"`
	Revision     int64         `json:"revision"`
	UpdatedAt    time.Time     `json:"updated_at"`
}

type DeploymentStatus string

const (
	DeploymentDraft            DeploymentStatus = "draft"
	DeploymentValidated        DeploymentStatus = "validated"
	DeploymentStaged           DeploymentStatus = "staged"
	DeploymentApplying         DeploymentStatus = "applying"
	DeploymentVerifying        DeploymentStatus = "verifying"
	DeploymentApplied          DeploymentStatus = "applied"
	DeploymentPartiallyApplied DeploymentStatus = "partially_applied"
	DeploymentFailed           DeploymentStatus = "failed"
	DeploymentOutcomeUnknown   DeploymentStatus = "outcome_unknown"
)

type Deployment struct {
	ID                 string           `json:"id"`
	GatewayID          string           `json:"gateway_id"`
	Generation         int64            `json:"generation"`
	ManifestHash       string           `json:"manifest_hash"`
	Status             DeploymentStatus `json:"status"`
	DesiredRevision    int64            `json:"desired_revision"`
	ObservedGeneration int64            `json:"observed_generation"`
	Error              string           `json:"error,omitempty"`
	CreatedAt          time.Time        `json:"created_at"`
	UpdatedAt          time.Time        `json:"updated_at"`
}

type OperationStatus string

const (
	OperationPending          OperationStatus = "pending"
	OperationRunning          OperationStatus = "running"
	OperationSucceeded        OperationStatus = "succeeded"
	OperationFailed           OperationStatus = "failed"
	OperationPartiallyApplied OperationStatus = "partially_applied"
	OperationOutcomeUnknown   OperationStatus = "outcome_unknown"
)

type Operation struct {
	ID                  string          `json:"id"`
	IdempotencyKey      string          `json:"idempotency_key,omitempty"`
	Target              string          `json:"target"`
	RequestedGeneration int64           `json:"requested_generation,omitempty"`
	Status              OperationStatus `json:"status"`
	Journal             []string        `json:"journal"`
	Result              any             `json:"result,omitempty"`
	Error               string          `json:"error,omitempty"`
	CreatedAt           time.Time       `json:"created_at"`
	UpdatedAt           time.Time       `json:"updated_at"`
}

type AuditEvent struct {
	ID           string    `json:"id"`
	Actor        string    `json:"actor"`
	ObjectType   string    `json:"object_type"`
	ObjectID     string    `json:"object_id"`
	Action       string    `json:"action"`
	RedactedDiff any       `json:"redacted_diff,omitempty"`
	Outcome      string    `json:"outcome"`
	CreatedAt    time.Time `json:"created_at"`
}

type Capabilities struct {
	Version      string            `json:"version"`
	Features     map[string]bool   `json:"features"`
	Restrictions map[string]string `json:"restrictions,omitempty"`
}
