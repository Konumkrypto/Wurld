-- Lifemindwurld progression: server-authoritative XP, LifeCoins, missions, leaderboards.
-- Run in the Supabase SQL editor. The browser can only CALL the rpc functions at the bottom.
-- LifeCoins are virtual entertainment points only: not cash, not cryptocurrency, never withdrawable.
create extension if not exists pgcrypto;

-- ===== Catalog (read-only to clients) =====
create table missions(
  id text primary key,
  type text not null check (type in ('daily','city','game','exploration','social','event')),
  title text not null, description text not null,
  goal jsonb not null,                       -- {"k":"checkins","n":3} | {"k":"plays","game":"trivia","xmin":7,"n":1} | {"k":"refs","refs":["wc1"]}
  xp int not null check (xp >= 0), coins int not null check (coins >= 0),
  period text not null check (period in ('daily','once','event')),
  starts_at timestamptz, ends_at timestamptz, city_id text, active boolean not null default true);

-- ===== Facts reported by the client, validated by functions =====
create table game_sessions(
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users on delete cascade,
  game_id text not null, started_at timestamptz not null default now(),
  consumed_at timestamptz);                  -- set once: a session can pay out exactly once (replay protection)
create table progress_events(
  id bigserial primary key,
  user_id uuid not null references auth.users on delete cascade,
  type text not null check (type in ('checkin','game')),
  ref text not null, value int not null default 0, extra int not null default 0,
  dedupe_key text not null, created_at timestamptz not null default now(),
  unique (user_id, dedupe_key));             -- e.g. checkin:<loc>:<yyyy-mm-dd>, game:<session>

-- ===== Immutable, hash-chained reward ledger =====
create table reward_ledger(
  id bigserial primary key,
  user_id uuid not null references auth.users on delete cascade,
  seq int not null, idem_key text not null,  -- unique per user: duplicate claims are impossible
  source text not null, ref text not null, city_id text,
  xp int not null check (xp >= 0), coins int not null check (coins >= 0),
  prev_hash text not null, hash text not null, created_at timestamptz not null default now(),
  unique (user_id, idem_key), unique (user_id, seq));

create or replace function ledger_chain() returns trigger language plpgsql as $$
declare last_row reward_ledger;
begin
  perform pg_advisory_xact_lock(hashtextextended(new.user_id::text, 1));   -- serialises concurrent writes per user
  select * into last_row from reward_ledger where user_id = new.user_id order by seq desc limit 1;
  new.seq := coalesce(last_row.seq, 0) + 1;
  new.prev_hash := coalesce(last_row.hash, '0');
  new.created_at := now();
  new.hash := encode(digest(new.prev_hash || '|' || new.seq || '|' || new.idem_key || '|' || new.source || '|' ||
              new.ref || '|' || new.xp || '|' || new.coins || '|' || new.created_at::text, 'sha256'), 'hex');
  return new;
end $$;
create trigger ledger_chain_t before insert on reward_ledger for each row execute function ledger_chain();

create or replace function ledger_immutable() returns trigger language plpgsql as $$
begin raise exception 'reward_ledger is append-only'; end $$;
create trigger ledger_no_change before update or delete on reward_ledger for each row execute function ledger_immutable();
create trigger ledger_no_truncate before truncate on reward_ledger for each statement execute function ledger_immutable();

create table mission_claims(
  user_id uuid not null references auth.users on delete cascade,
  mission_id text not null references missions, period_key text not null,   -- 'all' | yyyy-mm-dd | 'ev'
  ledger_id bigint not null references reward_ledger, claimed_at timestamptz not null default now(),
  primary key (user_id, mission_id, period_key));                          -- the duplicate-claim guard

-- Balances are DERIVED from the ledger. There is no xp/coins column anyone could update.
create view player_balances with (security_invoker = true) as
  select user_id, sum(xp)::int as xp, sum(coins)::int as coins, (sum(xp) / 100 + 1)::int as level
  from reward_ledger group by user_id;

-- ===== Row Level Security: clients may only READ their own rows. No insert/update/delete policies exist. =====
alter table missions enable row level security;         create policy missions_read on missions for select using (active);
alter table game_sessions enable row level security;    create policy gs_own on game_sessions for select using (user_id = auth.uid());
alter table progress_events enable row level security;  create policy pe_own on progress_events for select using (user_id = auth.uid());
alter table reward_ledger enable row level security;    create policy rl_own on reward_ledger for select using (user_id = auth.uid());
alter table mission_claims enable row level security;   create policy mc_own on mission_claims for select using (user_id = auth.uid());
revoke insert, update, delete, truncate on missions, game_sessions, progress_events, reward_ledger, mission_claims from anon, authenticated;

-- ===== Internal: idempotent grant (not callable by clients) =====
create or replace function grant_reward(p_user uuid, p_key text, p_src text, p_ref text, p_city text, p_xp int, p_coins int)
returns boolean language plpgsql security definer set search_path = public as $$
begin
  insert into reward_ledger(user_id, idem_key, source, ref, city_id, xp, coins, seq, prev_hash, hash)
  values (p_user, p_key, p_src, p_ref, p_city, p_xp, p_coins, 0, '', '')
  on conflict (user_id, idem_key) do nothing;
  return found;
end $$;
revoke execute on function grant_reward from public, anon, authenticated;

-- ===== Progress is computed from validated events, never sent by the client =====
create or replace function mission_progress(p_user uuid, m missions) returns int language sql stable security definer set search_path = public as $$
  select case m.goal->>'k'
    when 'checkins' then (select count(distinct ref) from progress_events e where e.user_id = p_user and e.type = 'checkin' and in_period(e.created_at, m))
    when 'plays'    then (select count(*) from progress_events e where e.user_id = p_user and e.type = 'game'
                          and (m.goal->>'game' is null or e.ref = m.goal->>'game')
                          and (m.goal->>'xmin' is null or e.extra >= (m.goal->>'xmin')::int)
                          and (m.goal->>'xmax' is null or e.extra <= (m.goal->>'xmax')::int) and in_period(e.created_at, m))
    when 'refs'     then (select count(distinct ref) from progress_events e where e.user_id = p_user and e.type = 'checkin'
                          and e.ref in (select jsonb_array_elements_text(m.goal->'refs')) and in_period(e.created_at, m))
    when 'landmarks' then (select count(distinct e.ref) from progress_events e join world_locations l on l.id::text = e.ref
                          where e.user_id = p_user and e.type = 'checkin' and l.category = 'landmark' and in_period(e.created_at, m))
    when 'districts' then (select count(distinct l.district_id) from progress_events e join world_locations l on l.id::text = e.ref
                          where e.user_id = p_user and e.type = 'checkin' and in_period(e.created_at, m))
    else 0 end::int
$$;
create or replace function in_period(t timestamptz, m missions) returns boolean language sql immutable as $$
  select case m.period when 'daily' then (t at time zone 'utc')::date = (now() at time zone 'utc')::date
                       when 'event' then t between m.starts_at and m.ends_at else true end $$;

-- ===== Client-callable RPCs (security definer; identity comes from auth.uid(), never from parameters) =====
create or replace function claim_mission(p_mission text) returns jsonb language plpgsql security definer set search_path = public as $$
declare uid uuid := auth.uid(); m missions; pk text; need int; lid bigint;
begin
  if uid is null then raise exception 'sign in required'; end if;
  perform pg_advisory_xact_lock(hashtextextended(uid::text || ':claim', 2));      -- simultaneous claims queue up here
  select * into m from missions where id = p_mission and active;
  if not found then raise exception 'unknown mission'; end if;
  if m.type = 'social' then raise exception 'not available yet'; end if;
  if m.period = 'event' and now() not between m.starts_at and m.ends_at then raise exception 'event not running'; end if;
  pk := case m.period when 'daily' then to_char(now() at time zone 'utc', 'YYYY-MM-DD') when 'event' then 'ev' else 'all' end;
  need := coalesce((m.goal->>'n')::int, jsonb_array_length(m.goal->'refs'));
  if mission_progress(uid, m) < need then raise exception 'mission not complete'; end if;
  if not grant_reward(uid, 'claim:' || m.id || ':' || pk, 'mission', m.id, m.city_id, m.xp, m.coins) then raise exception 'already claimed'; end if;
  select id into lid from reward_ledger where user_id = uid and idem_key = 'claim:' || m.id || ':' || pk;
  insert into mission_claims(user_id, mission_id, period_key, ledger_id) values (uid, m.id, pk, lid);   -- PK is a second duplicate guard
  return jsonb_build_object('xp', m.xp, 'coins', m.coins);
end $$;

create or replace function start_game(p_game text) returns uuid language sql security definer set search_path = public as $$
  insert into game_sessions(user_id, game_id) values (auth.uid(), p_game) returning id $$;

create or replace function complete_game(p_session uuid, p_result jsonb) returns jsonb language plpgsql security definer set search_path = public as $$
declare uid uuid := auth.uid(); s game_sessions; xp int := 0; c int := 0; x int := 0; secs numeric; today int;
begin
  select * into s from game_sessions where id = p_session and user_id = uid for update;   -- row lock: no parallel double-payout
  if not found or s.consumed_at is not null then raise exception 'invalid or used session'; end if;
  update game_sessions set consumed_at = now() where id = s.id;
  secs := extract(epoch from now() - s.started_at);
  -- Production note: trivia/memory answers should be checked against server-held state, not a self-reported score.
  if s.game_id = 'trivia' then
    x := (p_result->>'ok')::int; if secs < 10 or x not between 0 and 10 then raise exception 'rejected'; end if;
    xp := least(100, x * 10); c := least(25, floor(x * 2.5));
  elsif s.game_id = 'memory' then
    x := (p_result->>'moves')::int; if secs < 12 or x not between 8 and 300 then raise exception 'rejected'; end if;
    xp := greatest(30, least(100, 100 - (x - 8) * 7)); c := greatest(5, least(25, 25 - (x - 8) * 2));
  elsif s.game_id = 'hunt' then
    if secs < 15 then raise exception 'rejected'; end if; xp := 120; c := 30;
  else raise exception 'unknown game'; end if;
  insert into progress_events(user_id, type, ref, value, extra, dedupe_key) values (uid, 'game', s.game_id, coalesce((p_result->>'score')::int, 0), x, 'game:' || s.id);
  select count(*) into today from reward_ledger where user_id = uid and source = 'game' and created_at::date = current_date;
  if today >= 10 then return jsonb_build_object('xp', 0, 'coins', 0, 'note', 'daily reward limit reached'); end if;
  perform grant_reward(uid, 'game:' || s.id, 'game', s.game_id, null, xp, c);
  return jsonb_build_object('xp', xp, 'coins', c);
end $$;

create or replace function record_checkin(p_location text, p_x numeric, p_y numeric) returns jsonb language plpgsql security definer set search_path = public as $$
declare uid uuid := auth.uid(); l world_locations; first boolean;
begin
  select * into l from world_locations where id::text = p_location;
  if not found then raise exception 'unknown location'; end if;
  if sqrt((p_x - l.x - .5)^2 + (p_y - l.y - .5)^2) > 3.5 then raise exception 'walk closer'; end if;   -- plausibility check only
  insert into progress_events(user_id, type, ref, dedupe_key) values (uid, 'checkin', p_location, 'checkin:' || p_location || ':' || current_date)
    on conflict (user_id, dedupe_key) do nothing;
  if not found then raise exception 'already checked in today'; end if;
  first := grant_reward(uid, 'checkin:' || p_location, 'checkin', p_location, l.city_id, 10, 2);
  return jsonb_build_object('xp', case when first then 10 else 0 end, 'coins', case when first then 2 else 0 end);
end $$;
grant execute on function claim_mission, start_game, complete_game, record_checkin to authenticated;

-- ===== Leaderboards from ledger totals. Exposes only username, avatar, level, xp (no ids, emails, balances of coins). =====
create view leaderboard_global with (security_invoker = false) as
  select p.username, p.avatar, (sum(r.xp) / 100 + 1)::int as level, sum(r.xp)::int as xp,
         rank() over (order by sum(r.xp) desc) as rank
  from reward_ledger r join profiles p on p.id = r.user_id group by p.id, p.username, p.avatar;
create view leaderboard_city with (security_invoker = false) as
  select r.city_id, p.username, p.avatar, sum(r.xp)::int as xp,
         rank() over (partition by r.city_id order by sum(r.xp) desc) as rank
  from reward_ledger r join profiles p on p.id = r.user_id where r.city_id is not null group by r.city_id, p.id, p.username, p.avatar;
grant select on leaderboard_global, leaderboard_city to anon, authenticated;
-- At scale, replace with materialized views refreshed every minute (pg_cron) and add indexes on reward_ledger(city_id, user_id).
