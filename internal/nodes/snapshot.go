package nodes

import (
	"encoding/json"
	"errors"
	"fmt"
)

// These private representations intentionally restore fields omitted from
// public JSON. Only MarshalPrivate may serialize them for encrypted storage.
type privateDefinition struct {
	Definition
	Username string            `json:"username"`
	Password string            `json:"password"`
	UUID     string            `json:"uuid"`
	Headers  map[string]string `json:"headers"`
	Extra    map[string]string `json:"extra"`
}

func definitionForSnapshot(d Definition) privateDefinition {
	return privateDefinition{
		Definition: d, Username: d.Username, Password: d.Password,
		UUID: d.UUID, Headers: d.Headers, Extra: d.Extra,
	}
}

func (d privateDefinition) restore() Definition {
	d.Definition.Username = d.Username
	d.Definition.Password = d.Password
	d.Definition.UUID = d.UUID
	d.Definition.Headers = d.Headers
	d.Definition.Extra = d.Extra
	return d.Definition
}

type privateNode struct {
	Node
	Identity    string            `json:"identity"`
	ContentHash string            `json:"content_hash"`
	Definition  privateDefinition `json:"definition"`
}

type privateSnapshot struct {
	Version int           `json:"version"`
	Nodes   []privateNode `json:"nodes"`
}

// MarshalPrivate serializes complete nodes, including plaintext credentials and
// credential-derived hashes. The caller MUST encrypt the returned bytes before
// persisting them. They must never be returned in an API response or logged.
func MarshalPrivate(in []Node) ([]byte, error) {
	snapshot := privateSnapshot{Version: 1}
	if in != nil {
		snapshot.Nodes = make([]privateNode, len(in))
	}
	for i, n := range in {
		snapshot.Nodes[i] = privateNode{
			Node: n, Identity: n.Identity, ContentHash: n.ContentHash,
			Definition: definitionForSnapshot(n.Definition),
		}
	}
	return json.Marshal(snapshot)
}

// UnmarshalPrivate restores decrypted private storage bytes. The caller must
// authenticate and decrypt storage before passing it here; the returned nodes
// contain plaintext credentials and must remain inside trusted adapter code.
func UnmarshalPrivate(raw []byte) ([]Node, error) {
	var snapshot privateSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return nil, errors.New("invalid private node snapshot")
	}
	if snapshot.Version != 1 {
		return nil, errors.New("unsupported private node snapshot version")
	}
	var out []Node
	if snapshot.Nodes != nil {
		out = make([]Node, len(snapshot.Nodes))
	}
	for i, stored := range snapshot.Nodes {
		n := stored.Node
		n.Identity, n.ContentHash = stored.Identity, stored.ContentHash
		n.Definition = stored.Definition.restore()
		if n.ID == "" || n.ProviderID == "" || n.Identity == "" || n.ContentHash == "" || n.Revision < 1 {
			return nil, fmt.Errorf("private node snapshot entry %d is incomplete", i)
		}
		if _, err := Normalize(n.Definition); err != nil {
			return nil, fmt.Errorf("private node snapshot entry %d has an invalid definition", i)
		}
		if ContentFingerprint(n.Definition) != n.ContentHash {
			return nil, fmt.Errorf("private node snapshot entry %d has an invalid content hash", i)
		}
		out[i] = n
	}
	return out, nil
}
