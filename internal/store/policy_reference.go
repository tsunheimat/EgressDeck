package store

import (
	"context"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
)

// PolicyReferenceStore synchronizes the normalized policy identity referenced
// by device groups. The lifecycle service retains the full encrypted policy
// document (including ordered rules) through DocumentStore. Backends with
// relational constraints implement this optional interface.
type PolicyReferenceStore interface {
	SavePolicyReference(context.Context, domain.Policy) error
	DeletePolicyReference(context.Context, string) error
}

var _ PolicyReferenceStore = (*PostgresStore)(nil)

func (s *PostgresStore) SavePolicyReference(ctx context.Context, p domain.Policy) error {
	if p.ID == "" || p.Name == "" || p.Revision < 1 {
		return &domain.ValidationError{Problems: []string{"policy reference requires id, name and positive revision"}}
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO policies (id,name,default_action,unknown_domain_action,proxy_failure_action,revision)
VALUES ($1,$2,$3,$4,$5,$6)
ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name,default_action=EXCLUDED.default_action,
unknown_domain_action=EXCLUDED.unknown_domain_action,proxy_failure_action=EXCLUDED.proxy_failure_action,revision=EXCLUDED.revision`,
		p.ID, p.Name, p.DefaultAction, p.UnknownDomainAction, p.ProxyFailureAction, p.Revision)
	return err
}

func (s *PostgresStore) DeletePolicyReference(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM policies WHERE id=$1`, id)
	return err
}
