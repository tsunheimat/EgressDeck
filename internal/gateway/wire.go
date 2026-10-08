package gateway

// ProviderStageRequest is a private management-channel request. Its node
// connections may contain credentials. Never log, journal, or return it.
type ProviderStageRequest struct {
	ProviderID         string              `json:"provider_id"`
	Revision           int64               `json:"revision"`
	ContentHash        string              `json:"content_hash"`
	Nodes              []ProviderStageNode `json:"nodes"`
	Groups             []PublicationGroup  `json:"groups,omitempty"`
	AllowEmpty         bool                `json:"allow_empty,omitempty"`
	ExpectedGeneration int64               `json:"expected_generation"`
}
type ProviderStageNode struct {
	Node
	Connection string `json:"connection,omitempty"`
}

func NewProviderStageRequest(revision ProviderRevision, expected int64) ProviderStageRequest {
	out := ProviderStageRequest{ProviderID: revision.ProviderID, Revision: revision.Revision, ContentHash: revision.ContentHash, Groups: revision.Groups, AllowEmpty: revision.AllowEmpty, ExpectedGeneration: expected, Nodes: make([]ProviderStageNode, len(revision.Nodes))}
	for i, n := range revision.Nodes {
		out.Nodes[i] = ProviderStageNode{Node: n, Connection: n.Connection}
	}
	return out
}
func (r ProviderStageRequest) ProviderRevision() ProviderRevision {
	out := ProviderRevision{ProviderID: r.ProviderID, Revision: r.Revision, ContentHash: r.ContentHash, Groups: r.Groups, AllowEmpty: r.AllowEmpty, Nodes: make([]Node, len(r.Nodes))}
	for i, n := range r.Nodes {
		out.Nodes[i] = n.Node
		out.Nodes[i].Connection = n.Connection
	}
	return out
}
