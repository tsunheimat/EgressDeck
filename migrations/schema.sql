-- Homelab Proxy Controller, PostgreSQL schema
--
-- This file is deliberately safe to run more than once.  It is a bootstrap
-- migration for a new installation; subsequent migrations should use the same
-- `schema_migrations` table and a new monotonically increasing version.
--
-- IDs are UUIDs so references remain stable when a provider or gateway is
-- replaced.  Secret values are never logged or stored in ordinary JSON fields.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version       bigint PRIMARY KEY,
    applied_at    timestamptz NOT NULL DEFAULT now(),
    description   text NOT NULL DEFAULT ''
);

-- Versioned application-service snapshots complement the normalized inventory
-- tables. The single active controller serializes updates to each key.
CREATE TABLE IF NOT EXISTS controller_documents (
    key                   text PRIMARY KEY CHECK (length(key) BETWEEN 1 AND 200),
    document              jsonb NOT NULL,
    updated_at            timestamptz NOT NULL DEFAULT now()
);

-- A gateway is the independently managed dae data-plane endpoint.
CREATE TABLE IF NOT EXISTS gateways (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name                  text NOT NULL CHECK (length(btrim(name)) > 0),
    endpoint              text NOT NULL CHECK (length(btrim(endpoint)) > 0),
    adapter               text NOT NULL DEFAULT 'dae' CHECK (length(btrim(adapter)) > 0),
    adapter_version       text,
    capabilities          jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(capabilities) = 'object'),
    desired_generation    bigint NOT NULL DEFAULT 0 CHECK (desired_generation >= 0),
    observed_generation   bigint NOT NULL DEFAULT 0 CHECK (observed_generation >= 0),
    health_state          text NOT NULL DEFAULT 'unknown' CHECK (health_state IN ('unknown', 'healthy', 'degraded', 'unreachable')),
    enabled               boolean NOT NULL DEFAULT true,
    revision              bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now()
);

-- Provider and node identity are separate from immutable content revisions.
CREATE TABLE IF NOT EXISTS secret_metadata (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_ref            text NOT NULL UNIQUE CHECK (length(btrim(secret_ref)) > 0),
    kind                  text NOT NULL CHECK (length(btrim(kind)) > 0),
    encryption_key_id     text NOT NULL CHECK (length(btrim(encryption_key_id)) > 0),
    key_version           integer NOT NULL DEFAULT 1 CHECK (key_version > 0),
    encrypted_payload     bytea,
    metadata              jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(metadata) = 'object'),
    created_at            timestamptz NOT NULL DEFAULT now(),
    rotated_at            timestamptz,
    last_used_at          timestamptz,
    revoked_at            timestamptz,
    CHECK (rotated_at IS NULL OR rotated_at >= created_at),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

COMMENT ON TABLE secret_metadata IS
    'Metadata and encrypted material references only; the application encryption key stays outside PostgreSQL backups.';
COMMENT ON COLUMN secret_metadata.encrypted_payload IS
    'Optional ciphertext. Never place plaintext credentials in this table, operation payloads, or audit diffs.';

CREATE TABLE IF NOT EXISTS providers (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name                  text NOT NULL CHECK (length(btrim(name)) > 0),
    source_kind           text NOT NULL DEFAULT 'url' CHECK (source_kind IN ('url', 'file', 'local', 'manual', 'subscription')),
    source               text NOT NULL CHECK (length(btrim(source)) > 0),
    format                text NOT NULL DEFAULT 'auto' CHECK (length(btrim(format)) > 0),
    secret_id             uuid REFERENCES secret_metadata(id) ON DELETE SET NULL,
    fetch_route           text NOT NULL DEFAULT 'direct' CHECK (length(btrim(fetch_route)) > 0),
    refresh_interval      interval,
    auto_apply            boolean NOT NULL DEFAULT false,
    active_revision_id    uuid,
    staged_revision_id    uuid,
    state                 text NOT NULL DEFAULT 'configured' CHECK (state IN ('configured', 'fetching', 'staged', 'active', 'error', 'disabled')),
    last_attempt_at       timestamptz,
    last_success_at       timestamptz,
    last_error            text,
    revision              bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    CHECK (refresh_interval IS NULL OR refresh_interval > interval '0')
);

CREATE TABLE IF NOT EXISTS provider_revisions (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id           uuid NOT NULL REFERENCES providers(id) ON DELETE CASCADE,
    revision_number       bigint NOT NULL CHECK (revision_number > 0),
    content_hash          text NOT NULL CHECK (length(btrim(content_hash)) > 0),
    normalized_inventory  jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(normalized_inventory) = 'object'),
    parse_report          jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(parse_report) = 'object'),
    unsupported_count     integer NOT NULL DEFAULT 0 CHECK (unsupported_count >= 0),
    node_count            integer NOT NULL DEFAULT 0 CHECK (node_count >= 0),
    state                 text NOT NULL DEFAULT 'staged' CHECK (state IN ('staged', 'active', 'failed', 'retired')),
    fetched_at            timestamptz NOT NULL DEFAULT now(),
    approved_at           timestamptz,
    activated_at          timestamptz,
    failed_at             timestamptz,
    error                 text,
    UNIQUE (provider_id, revision_number),
    UNIQUE (provider_id, content_hash)
);

CREATE TABLE IF NOT EXISTS nodes (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id           uuid NOT NULL REFERENCES providers(id) ON DELETE CASCADE,
    identity              text NOT NULL CHECK (length(btrim(identity)) > 0),
    display_name          text NOT NULL CHECK (length(btrim(display_name)) > 0),
    protocol              text,
    secret_id             uuid REFERENCES secret_metadata(id) ON DELETE SET NULL,
    active_revision_id    uuid,
    state                 text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'unsupported', 'retired')),
    revision              bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider_id, identity)
);

CREATE TABLE IF NOT EXISTS node_revisions (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id               uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    provider_revision_id  uuid REFERENCES provider_revisions(id) ON DELETE SET NULL,
    revision_number       bigint NOT NULL CHECK (revision_number > 0),
    definition            jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(definition) = 'object'),
    content_hash          text NOT NULL CHECK (length(btrim(content_hash)) > 0),
    protocol_capabilities jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(protocol_capabilities) = 'object'),
    supported              boolean NOT NULL DEFAULT true,
    created_at            timestamptz NOT NULL DEFAULT now(),
    UNIQUE (node_id, revision_number),
    UNIQUE (node_id, content_hash)
);

-- Outbound groups contain candidate nodes.  They are intentionally distinct
-- from device groups so shared and independent selection have clear identity.
CREATE TABLE IF NOT EXISTS outbound_groups (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name                  text NOT NULL CHECK (length(btrim(name)) > 0),
    gateway_id            uuid NOT NULL REFERENCES gateways(id) ON DELETE RESTRICT,
    selection_mode        text NOT NULL DEFAULT 'manual' CHECK (selection_mode IN ('manual', 'automatic')),
    replacement_policy    text NOT NULL DEFAULT 'block' CHECK (replacement_policy IN ('block', 'explicit', 'automatic')),
    desired_revision      bigint NOT NULL DEFAULT 1 CHECK (desired_revision > 0),
    applied_revision      bigint,
    observed_revision     bigint,
    verified_revision     bigint,
    enabled               boolean NOT NULL DEFAULT true,
    revision              bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    UNIQUE (id, gateway_id)
);

CREATE TABLE IF NOT EXISTS outbound_group_nodes (
    outbound_group_id     uuid NOT NULL REFERENCES outbound_groups(id) ON DELETE CASCADE,
    node_id               uuid NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
    position              integer NOT NULL DEFAULT 0 CHECK (position >= 0),
    enabled               boolean NOT NULL DEFAULT true,
    PRIMARY KEY (outbound_group_id, node_id)
);

CREATE TABLE IF NOT EXISTS outbound_selections (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    outbound_group_id     uuid NOT NULL REFERENCES outbound_groups(id) ON DELETE CASCADE,
    gateway_id            uuid NOT NULL REFERENCES gateways(id) ON DELETE RESTRICT,
    transport_scope       text NOT NULL DEFAULT 'all' CHECK (length(btrim(transport_scope)) > 0),
    desired_node_id       uuid REFERENCES nodes(id) ON DELETE RESTRICT,
    applied_node_id       uuid REFERENCES nodes(id) ON DELETE RESTRICT,
    observed_node_id      uuid REFERENCES nodes(id) ON DELETE RESTRICT,
    verified_node_id      uuid REFERENCES nodes(id) ON DELETE RESTRICT,
    desired_revision      bigint NOT NULL DEFAULT 1 CHECK (desired_revision > 0),
    applied_revision      bigint,
    observed_revision     bigint,
    verified_revision     bigint,
    replacement_policy    text NOT NULL DEFAULT 'block' CHECK (replacement_policy IN ('block', 'explicit', 'automatic')),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    UNIQUE (outbound_group_id, gateway_id, transport_scope)
);

CREATE TABLE IF NOT EXISTS policies (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name                  text NOT NULL CHECK (length(btrim(name)) > 0),
    default_action        text NOT NULL CHECK (default_action IN ('direct', 'proxy', 'block', 'outbound_group')),
    unknown_domain_action text NOT NULL CHECK (unknown_domain_action IN ('direct', 'proxy', 'block', 'outbound_group')),
    proxy_failure_action  text NOT NULL CHECK (proxy_failure_action IN ('direct', 'proxy', 'block', 'outbound_group')),
    revision              bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS rule_sets (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name                  text NOT NULL CHECK (length(btrim(name)) > 0),
    description           text NOT NULL DEFAULT '',
    revision              bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS rules (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id             uuid REFERENCES policies(id) ON DELETE CASCADE,
    rule_set_id           uuid REFERENCES rule_sets(id) ON DELETE CASCADE,
    position              integer NOT NULL DEFAULT 0 CHECK (position >= 0),
    name                  text NOT NULL CHECK (length(btrim(name)) > 0),
    match_expression      jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(match_expression) = 'object'),
    action                text NOT NULL CHECK (action IN ('direct', 'proxy', 'block', 'outbound_group')),
    outbound_group_id     uuid REFERENCES outbound_groups(id) ON DELETE RESTRICT,
    enabled               boolean NOT NULL DEFAULT true,
    revision              bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    CHECK ((policy_id IS NOT NULL) <> (rule_set_id IS NOT NULL)),
    CHECK (action <> 'outbound_group' OR outbound_group_id IS NOT NULL),
    UNIQUE (policy_id, position),
    UNIQUE (rule_set_id, position)
);

CREATE TABLE IF NOT EXISTS devices (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name                  text NOT NULL CHECK (length(btrim(name)) > 0),
    network_scope         text NOT NULL DEFAULT 'default',
    -- The FK is installed after device_groups is created below because the
    -- two records refer to each other during bootstrap.
    primary_group_id      uuid,
    exceptions            jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(exceptions) = 'array'),
    enrollment_state      text NOT NULL DEFAULT 'unenrolled' CHECK (enrollment_state IN ('unenrolled', 'pending', 'enrolled', 'blocked')),
    revision              bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now()
);

-- Preserve upgrades from controller versions that stored no device exceptions.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS exceptions jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(exceptions) = 'array');

CREATE TABLE IF NOT EXISTS device_addresses (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id             uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    family                text NOT NULL CHECK (family IN ('ipv4', 'ipv6')),
    address               inet NOT NULL,
    provenance            text NOT NULL DEFAULT 'manual',
    validity_state        text NOT NULL DEFAULT 'unverified' CHECK (validity_state IN ('unverified', 'valid', 'invalid', 'expired')),
    verified_at           timestamptz,
    UNIQUE (address),
    UNIQUE (device_id, address)
);

CREATE TABLE IF NOT EXISTS device_groups (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name                  text NOT NULL CHECK (length(btrim(name)) > 0),
    gateway_id            uuid NOT NULL REFERENCES gateways(id) ON DELETE RESTRICT,
    policy_id             uuid NOT NULL REFERENCES policies(id) ON DELETE RESTRICT,
    enabled               boolean NOT NULL DEFAULT true,
    desired_revision      bigint NOT NULL DEFAULT 1 CHECK (desired_revision > 0),
    applied_revision      bigint,
    observed_revision     bigint,
    verified_revision     bigint,
    revision              bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    UNIQUE (gateway_id, name)
);

CREATE TABLE IF NOT EXISTS device_group_members (
    device_group_id       uuid NOT NULL REFERENCES device_groups(id) ON DELETE CASCADE,
    device_id             uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    added_at              timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (device_group_id, device_id)
);

CREATE TABLE IF NOT EXISTS device_policy_exceptions (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id             uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    position              integer NOT NULL DEFAULT 0 CHECK (position >= 0),
    name                  text NOT NULL CHECK (length(btrim(name)) > 0),
    match_expression      jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(match_expression) = 'object'),
    action                text NOT NULL CHECK (action IN ('direct', 'proxy', 'block', 'outbound_group')),
    outbound_group_id     uuid REFERENCES outbound_groups(id) ON DELETE RESTRICT,
    enabled               boolean NOT NULL DEFAULT true,
    revision              bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    UNIQUE (device_id, position),
    CHECK (action <> 'outbound_group' OR outbound_group_id IS NOT NULL)
);

CREATE TABLE IF NOT EXISTS firewall_bindings (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    gateway_id            uuid NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
    family                text NOT NULL CHECK (family IN ('ipv4', 'ipv6')),
    interface_scope       text NOT NULL CHECK (length(btrim(interface_scope)) > 0),
    alias_name            text NOT NULL CHECK (length(btrim(alias_name)) > 0),
    rule_identifiers      jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(rule_identifiers) = 'array'),
    expected_shape        jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(expected_shape) = 'object'),
    desired_addresses     jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(desired_addresses) = 'array'),
    applied_addresses     jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(applied_addresses) = 'array'),
    observed_addresses    jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(observed_addresses) = 'array'),
    verified_at           timestamptz,
    state                 text NOT NULL DEFAULT 'unknown' CHECK (state IN ('unknown', 'desired', 'applied', 'drifted', 'verified', 'failed')),
    revision              bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    UNIQUE (gateway_id, family, interface_scope, alias_name)
);

-- A deployment is a controller-owned manifest.  Each state is recorded
-- separately so an accepted request cannot be mistaken for observed traffic.
CREATE TABLE IF NOT EXISTS deployments (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    gateway_id            uuid NOT NULL REFERENCES gateways(id) ON DELETE RESTRICT,
    operation_id          uuid,
    desired_manifest      jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(desired_manifest) = 'object'),
    applied_manifest      jsonb,
    observed_snapshot     jsonb,
    verified_result       jsonb,
    desired_generation    bigint NOT NULL CHECK (desired_generation > 0),
    applied_generation    bigint,
    observed_generation   bigint,
    verified_generation   bigint,
    desired_hash          text NOT NULL CHECK (length(btrim(desired_hash)) > 0),
    applied_hash          text,
    observed_hash         text,
    verified_hash         text,
    status                text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'validated', 'staged', 'applying', 'verifying', 'applied', 'partially_applied', 'failed', 'outcome_unknown')),
    error                 text,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now()
);

-- Generic state records cover policies, providers, groups, and deployments
-- that do not otherwise have a gateway-specific state column.
CREATE TABLE IF NOT EXISTS resource_states (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_type         text NOT NULL CHECK (length(btrim(resource_type)) > 0),
    resource_id           uuid NOT NULL,
    gateway_id            uuid REFERENCES gateways(id) ON DELETE CASCADE,
    state_kind            text NOT NULL CHECK (state_kind IN ('desired', 'applied', 'observed', 'verified')),
    revision              bigint NOT NULL CHECK (revision > 0),
    generation            bigint CHECK (generation IS NULL OR generation >= 0),
    content               jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(content) = 'object'),
    content_hash          text NOT NULL CHECK (length(btrim(content_hash)) > 0),
    status                text NOT NULL DEFAULT 'recorded' CHECK (status IN ('recorded', 'pending', 'success', 'failed', 'stale')),
    error                 text,
    operation_id          uuid,
    recorded_at           timestamptz NOT NULL DEFAULT now(),
    verified_at           timestamptz
);

CREATE UNIQUE INDEX IF NOT EXISTS resource_states_identity_idx
    ON resource_states (resource_type, resource_id, state_kind, revision, (COALESCE(gateway_id, '00000000-0000-0000-0000-000000000000'::uuid)));

CREATE TABLE IF NOT EXISTS operations (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    idempotency_key       text NOT NULL UNIQUE CHECK (length(btrim(idempotency_key)) > 0),
    action                text NOT NULL CHECK (length(btrim(action)) > 0),
    target_type           text NOT NULL CHECK (length(btrim(target_type)) > 0),
    target_id             uuid,
    gateway_id            uuid REFERENCES gateways(id) ON DELETE SET NULL,
    actor_id              text,
    actor_type            text NOT NULL DEFAULT 'user' CHECK (actor_type IN ('user', 'system', 'agent')),
    requested_generation  bigint CHECK (requested_generation IS NULL OR requested_generation >= 0),
    requested_revision    bigint CHECK (requested_revision IS NULL OR requested_revision > 0),
    status                text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'validated', 'staged', 'applying', 'verifying', 'applied', 'partially_applied', 'failed', 'outcome_unknown')),
    rollback_status       text NOT NULL DEFAULT 'none' CHECK (rollback_status IN ('none', 'pending', 'running', 'succeeded', 'failed')),
    request_payload       jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(request_payload) = 'object'),
    result_payload        jsonb,
    error                 text,
    started_at            timestamptz,
    finished_at           timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    CHECK (finished_at IS NULL OR started_at IS NULL OR finished_at >= started_at)
);

CREATE TABLE IF NOT EXISTS operation_steps (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    operation_id          uuid NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    sequence              integer NOT NULL CHECK (sequence >= 0),
    name                  text NOT NULL CHECK (length(btrim(name)) > 0),
    status                text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'succeeded', 'failed', 'outcome_unknown', 'skipped')),
    request_payload       jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(request_payload) = 'object'),
    result_payload        jsonb,
    error                 text,
    started_at            timestamptz,
    finished_at           timestamptz,
    UNIQUE (operation_id, sequence),
    CHECK (finished_at IS NULL OR started_at IS NULL OR finished_at >= started_at)
);

CREATE TABLE IF NOT EXISTS audit_events (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    operation_id          uuid REFERENCES operations(id) ON DELETE SET NULL,
    actor_id              text,
    actor_type            text NOT NULL DEFAULT 'system' CHECK (actor_type IN ('user', 'system', 'agent')),
    action                text NOT NULL CHECK (length(btrim(action)) > 0),
    object_type           text NOT NULL CHECK (length(btrim(object_type)) > 0),
    object_id             uuid,
    outcome               text NOT NULL CHECK (outcome IN ('accepted', 'applied', 'rejected', 'failed', 'drifted')),
    redacted_diff         jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(redacted_diff) = 'object'),
    metadata              jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(metadata) = 'object'),
    occurred_at           timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS management_events (
    id                    bigserial PRIMARY KEY,
    event_id              uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    event_type            text NOT NULL CHECK (length(btrim(event_type)) > 0),
    resource_type         text,
    resource_id           uuid,
    payload               jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(payload) = 'object'),
    created_at             timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS device_addresses_device_idx ON device_addresses (device_id);
CREATE INDEX IF NOT EXISTS device_groups_gateway_idx ON device_groups (gateway_id);
CREATE INDEX IF NOT EXISTS device_group_members_device_idx ON device_group_members (device_id);
CREATE INDEX IF NOT EXISTS provider_revisions_provider_state_idx ON provider_revisions (provider_id, state);
CREATE INDEX IF NOT EXISTS nodes_provider_idx ON nodes (provider_id);
CREATE INDEX IF NOT EXISTS node_revisions_provider_revision_idx ON node_revisions (provider_revision_id);
CREATE INDEX IF NOT EXISTS outbound_group_nodes_node_idx ON outbound_group_nodes (node_id);
CREATE INDEX IF NOT EXISTS outbound_selections_gateway_idx ON outbound_selections (gateway_id);
CREATE INDEX IF NOT EXISTS deployments_gateway_status_idx ON deployments (gateway_id, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS operations_status_idx ON operations (status, updated_at DESC);
CREATE INDEX IF NOT EXISTS operations_target_idx ON operations (target_type, target_id, created_at DESC);
CREATE INDEX IF NOT EXISTS operation_steps_operation_idx ON operation_steps (operation_id, sequence);
CREATE INDEX IF NOT EXISTS audit_events_object_idx ON audit_events (object_type, object_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS management_events_created_idx ON management_events (created_at DESC, id DESC);

-- The active/staged revision pointers are intentionally checked after both
-- tables exist.  A failed refresh may leave the old active revision in place.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'providers_active_revision_fk') THEN
        ALTER TABLE providers
            ADD CONSTRAINT providers_active_revision_fk
            FOREIGN KEY (active_revision_id) REFERENCES provider_revisions(id) ON DELETE SET NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'providers_staged_revision_fk') THEN
        ALTER TABLE providers
            ADD CONSTRAINT providers_staged_revision_fk
            FOREIGN KEY (staged_revision_id) REFERENCES provider_revisions(id) ON DELETE SET NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'nodes_active_revision_fk') THEN
        ALTER TABLE nodes
            ADD CONSTRAINT nodes_active_revision_fk
            FOREIGN KEY (active_revision_id) REFERENCES node_revisions(id) ON DELETE SET NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'devices_primary_group_fk') THEN
        ALTER TABLE devices
            ADD CONSTRAINT devices_primary_group_fk
            FOREIGN KEY (primary_group_id) REFERENCES device_groups(id) ON DELETE SET NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'outbound_selections_group_gateway_fk') THEN
        ALTER TABLE outbound_selections
            ADD CONSTRAINT outbound_selections_group_gateway_fk
            FOREIGN KEY (outbound_group_id, gateway_id)
            REFERENCES outbound_groups(id, gateway_id) ON DELETE CASCADE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'deployments_operation_fk') THEN
        ALTER TABLE deployments
            ADD CONSTRAINT deployments_operation_fk
            FOREIGN KEY (operation_id) REFERENCES operations(id) ON DELETE SET NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'resource_states_operation_fk') THEN
        ALTER TABLE resource_states
            ADD CONSTRAINT resource_states_operation_fk
            FOREIGN KEY (operation_id) REFERENCES operations(id) ON DELETE SET NULL;
    END IF;
END
$$;

CREATE OR REPLACE FUNCTION controller_set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$;

DO $$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'gateways', 'providers', 'nodes', 'outbound_groups', 'outbound_selections',
        'policies', 'rule_sets', 'rules', 'devices', 'device_groups',
        'firewall_bindings', 'deployments', 'operations'
    ] LOOP
        IF NOT EXISTS (
            SELECT 1
              FROM pg_trigger t
              JOIN pg_class c ON c.oid = t.tgrelid
              JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE t.tgname = table_name || '_set_updated_at'
               AND c.relname = table_name
               AND n.nspname = current_schema()
        ) THEN
            EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION controller_set_updated_at()', table_name || '_set_updated_at', table_name);
        END IF;
    END LOOP;
END
$$;

COMMENT ON TABLE resource_states IS
    'Durable desired/applied/observed/verified snapshots. A successful API write only creates desired state.';
COMMENT ON COLUMN deployments.observed_snapshot IS
    'Readback from the gateway/firewall; this is not inferred from a request acknowledgement.';
COMMENT ON COLUMN audit_events.redacted_diff IS
    'Redacted change summary. Do not serialize provider URLs with credentials, node links, or secret values.';
COMMENT ON TABLE operations IS
    'Replay-safe durable operation journal. outcome_unknown requires readback before retry or rollback.';

INSERT INTO schema_migrations (version, description)
VALUES (1, 'initial controller entities, revisions, state snapshots, operations, audit, and secret metadata')
ON CONFLICT (version) DO NOTHING;
