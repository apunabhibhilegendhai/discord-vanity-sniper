-- Dashboard schema for the self-hosted Supabase instance.
--
-- Access model:
--   * anon / authenticated: no table privileges and no permissive RLS policy.
--   * service_role: used only by the Next.js server; it bypasses RLS.
--   * dashboard admin authorization is the sniper_admins lookup, not "any
--     authenticated user". The server performs that lookup before every write.
--
-- Apply with psql -v ON_ERROR_STOP=1. The migration is intentionally
-- idempotent for a first install; it does not attempt destructive upgrades.
--
-- Hashing uses the built-in sha256(bytea) (PostgreSQL 11+) rather than
-- pgcrypto's digest(), because self-hosted Supabase installs pgcrypto in the
-- separate `extensions` schema. A SECURITY DEFINER function with a tight
-- search_path (public, pg_temp) cannot see it, and widening search_path just
-- to reach an extension is the wrong trade. gen_random_uuid() is built in
-- since PostgreSQL 13, so this migration needs no extension at all.

begin;

-- ---------------------------------------------------------------------------
-- Admin allow-list
-- ---------------------------------------------------------------------------

create table if not exists public.sniper_admins (
  user_id    uuid primary key references auth.users (id) on delete cascade,
  role       text not null default 'admin' check (role in ('admin')),
  active     boolean not null default true,
  created_at timestamptz not null default now(),
  created_by uuid references auth.users (id) on delete set null
);

comment on table public.sniper_admins is
  'Explicit dashboard administrators. No sign-up path inserts here.';

-- Bootstrap after the operator's first Supabase sign-in, once:
--   insert into public.sniper_admins (user_id, role)
--   values ('<auth.users.id>', 'admin');
-- Public sign-up must never be granted admin.

-- ---------------------------------------------------------------------------
-- Versioned config documents
-- ---------------------------------------------------------------------------

create table if not exists public.sniper_configs (
  id         uuid primary key default gen_random_uuid(),
  version    bigint not null check (version > 0),
  config     jsonb not null check (jsonb_typeof(config) = 'object'),
  active     boolean not null default false,
  author     uuid references auth.users (id) on delete set null,
  note       text,
  created_at timestamptz not null default now(),
  constraint sniper_configs_version_key unique (version)
);

-- At most one active row, so sniper-config-sync's active=eq.true lookup can
-- never return two documents.
create unique index if not exists sniper_configs_one_active
  on public.sniper_configs (active)
  where active;

create index if not exists sniper_configs_created_at_idx
  on public.sniper_configs (created_at desc);

comment on table public.sniper_configs is
  'Immutable config versions; exactly one row is active at a time.';

-- Encrypted secret values are stored apart from the config document so a
-- future config-sync renderer can decrypt only what it needs. The dashboard
-- currently writes plaintext config JSON because sniper-config-sync expects
-- that shape; see docs/dashboard.md for the deferred encryption boundary.
create table if not exists public.sniper_secrets (
  id             uuid primary key default gen_random_uuid(),
  config_version bigint not null references public.sniper_configs (version) on delete cascade,
  name           text not null check (length(name) between 1 and 64),
  ciphertext     text not null,
  created_at     timestamptz not null default now(),
  constraint sniper_secrets_version_name_key unique (config_version, name)
);

comment on table public.sniper_secrets is
  'Reserved for encrypted secret values keyed by config version.';

-- ---------------------------------------------------------------------------
-- Target inventory (read model for the dashboard; config remains authoritative)
-- ---------------------------------------------------------------------------

create table if not exists public.sniper_targets (
  guild_id       text primary key check (guild_id ~ '^[0-9]{17,20}$'),
  expected_vanity text not null,
  enabled        boolean not null default true,
  display_name   text,
  updated_at     timestamptz not null default now()
);

comment on table public.sniper_targets is
  'Optional dashboard read model of configured targets; sniper_configs.config is authoritative.';

-- ---------------------------------------------------------------------------
-- Audit trail
-- ---------------------------------------------------------------------------

create table if not exists public.sniper_audit (
  id          uuid primary key default gen_random_uuid(),
  actor       uuid references auth.users (id) on delete set null,
  action      text not null check (action in ('config.save', 'config.apply', 'restart', 'login')),
  target      text,
  before_hash text,
  after_hash  text,
  result      text not null default 'ok' check (result in ('ok', 'error')),
  detail      jsonb not null default '{}'::jsonb,
  ip          inet,
  created_at  timestamptz not null default now()
);

create index if not exists sniper_audit_created_at_idx
  on public.sniper_audit (created_at desc);

comment on table public.sniper_audit is
  'Who changed what, from where, and whether it succeeded.';

-- ---------------------------------------------------------------------------
-- Health sidecar state
-- ---------------------------------------------------------------------------

create table if not exists public.sniper_health (
  unit                   text primary key,
  status                 text not null default 'unknown',
  last_error             text,
  heartbeat_at           timestamptz,
  last_claim_at          timestamptz,
  last_guard_at          timestamptz,
  applied_config_version bigint,
  updated_at             timestamptz not null default now()
);

comment on table public.sniper_health is
  'One row per systemd unit, upserted by deploy/bin/sniper-health.';

-- ---------------------------------------------------------------------------
-- Optional command queue
-- ---------------------------------------------------------------------------

create table if not exists public.sniper_commands (
  id           uuid primary key default gen_random_uuid(),
  command      text not null check (command in ('restart', 'reload')),
  payload      jsonb not null default '{}'::jsonb,
  state        text not null default 'pending'
               check (state in ('pending', 'running', 'done', 'error', 'expired')),
  requested_by uuid references auth.users (id) on delete set null,
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now(),
  expires_at   timestamptz not null default (now() + interval '2 minutes')
);

create index if not exists sniper_commands_pending_idx
  on public.sniper_commands (state, created_at)
  where state = 'pending';

comment on table public.sniper_commands is
  'Optional idempotent queue; the dashboard restart route calls the fixed helper directly.';

-- ---------------------------------------------------------------------------
-- Atomic config activation
-- ---------------------------------------------------------------------------
-- Doing this through PostgREST as three separate requests can leave no active
-- row if the final patch fails. The function serializes writers, deactivates
-- the old row and inserts the new active row in one transaction, then records
-- the audit entry. It is executable only by service_role.

create or replace function public.sniper_save_config(
  p_config jsonb,
  p_author uuid,
  p_note text default null,
  p_ip inet default null
) returns public.sniper_configs
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_next bigint;
  v_before text;
  v_row public.sniper_configs;
begin
  if jsonb_typeof(p_config) <> 'object' then
    raise exception 'config must be a JSON object' using errcode = '22023';
  end if;

  -- Serialize version allocation and activation across concurrent admins.
  perform pg_advisory_xact_lock(hashtext('sniper_configs'));

  select coalesce(max(version), 0) + 1 into v_next
    from public.sniper_configs;

  select encode(sha256(convert_to(config::text, 'UTF8')), 'hex') into v_before
    from public.sniper_configs
   where active
   limit 1;

  update public.sniper_configs set active = false where active;

  insert into public.sniper_configs (version, config, active, author, note)
  values (v_next, p_config, true, p_author, left(p_note, 500))
  returning * into v_row;

  insert into public.sniper_audit (
    actor, action, target, before_hash, after_hash, result, detail, ip
  ) values (
    p_author,
    'config.save',
    'sniper_configs',
    v_before,
    encode(sha256(convert_to(p_config::text, 'UTF8')), 'hex'),
    'ok',
    jsonb_build_object('version', v_next),
    p_ip
  );

  return v_row;
end;
$$;

revoke all on function public.sniper_save_config(jsonb, uuid, text, inet)
  from public, anon, authenticated;
grant execute on function public.sniper_save_config(jsonb, uuid, text, inet)
  to service_role;

-- ---------------------------------------------------------------------------
-- Deny-by-default RLS and grants
-- ---------------------------------------------------------------------------
-- The explicit restrictive policy is documentation as well as enforcement:
-- even if a future grant is added by mistake, anon and authenticated still
-- cannot read or write these tables. service_role bypasses RLS and is granted
-- explicitly below.

alter table public.sniper_admins      enable row level security;
alter table public.sniper_configs     enable row level security;
alter table public.sniper_secrets     enable row level security;
alter table public.sniper_targets     enable row level security;
alter table public.sniper_audit       enable row level security;
alter table public.sniper_health      enable row level security;
alter table public.sniper_commands    enable row level security;

drop policy if exists "no client access" on public.sniper_admins;
drop policy if exists "no client access" on public.sniper_configs;
drop policy if exists "no client access" on public.sniper_secrets;
drop policy if exists "no client access" on public.sniper_targets;
drop policy if exists "no client access" on public.sniper_audit;
drop policy if exists "no client access" on public.sniper_health;
drop policy if exists "no client access" on public.sniper_commands;

create policy "no client access" on public.sniper_admins
  as restrictive for all to anon, authenticated
  using (false) with check (false);
create policy "no client access" on public.sniper_configs
  as restrictive for all to anon, authenticated
  using (false) with check (false);
create policy "no client access" on public.sniper_secrets
  as restrictive for all to anon, authenticated
  using (false) with check (false);
create policy "no client access" on public.sniper_targets
  as restrictive for all to anon, authenticated
  using (false) with check (false);
create policy "no client access" on public.sniper_audit
  as restrictive for all to anon, authenticated
  using (false) with check (false);
create policy "no client access" on public.sniper_health
  as restrictive for all to anon, authenticated
  using (false) with check (false);
create policy "no client access" on public.sniper_commands
  as restrictive for all to anon, authenticated
  using (false) with check (false);

revoke all on table public.sniper_admins   from public, anon, authenticated;
revoke all on table public.sniper_configs  from public, anon, authenticated;
revoke all on table public.sniper_secrets  from public, anon, authenticated;
revoke all on table public.sniper_targets  from public, anon, authenticated;
revoke all on table public.sniper_audit    from public, anon, authenticated;
revoke all on table public.sniper_health   from public, anon, authenticated;
revoke all on table public.sniper_commands from public, anon, authenticated;

grant all on table public.sniper_admins   to service_role;
grant all on table public.sniper_configs  to service_role;
grant all on table public.sniper_secrets  to service_role;
grant all on table public.sniper_targets  to service_role;
grant all on table public.sniper_audit    to service_role;
grant all on table public.sniper_health   to service_role;
grant all on table public.sniper_commands to service_role;

commit;
