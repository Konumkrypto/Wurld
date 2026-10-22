-- Lifemindwurld advertising: campaign state machine, manual approval, manual payment, measured metrics.
-- Run AFTER lifemindwurld_businesses.sql. This file REPLACES the simple ad_campaigns table created there.
-- Version 1 = manual approval + manual payment confirmation. Payment processing can be added later without changing the state machine.

alter table business_placements drop constraint if exists business_placements_campaign_id_fkey;
drop table if exists ad_campaigns cascade;

create type campaign_state as enum ('draft','submitted','under_review','approved','rejected','active','paused','completed');
create type ad_placement as enum ('featured_listing','billboard','sponsored_mission','game_challenge','featured_location');

-- Payments are their own table so a processor (Stripe, Paystack, ...) can be plugged in later: add a provider value, a webhook function that
-- inserts a payment_events row and flips payments.status. Campaign activation only ever checks payments.status = 'confirmed'.
create table payments(
  id uuid primary key default gen_random_uuid(),
  provider text not null default 'manual' check (provider in ('manual')),      -- extend this list when processing is added
  status text not null default 'awaiting' check (status in ('awaiting','confirmed','refunded','failed')),
  amount_minor bigint check (amount_minor is null or amount_minor >= 0), currency text,
  reference text,                                                                -- manual: bank-transfer reference; later: provider id
  confirmed_by uuid references auth.users, confirmed_at timestamptz, created_at timestamptz not null default now());
create table payment_events(id bigserial primary key, payment_id uuid not null references payments, kind text not null, payload jsonb, created_at timestamptz not null default now());

create table ad_campaigns(
  id uuid primary key default gen_random_uuid(),
  business_id uuid not null references businesses on delete cascade,
  city_id text not null references cities(id),
  placement ad_placement not null,
  location_id uuid references world_locations,                                  -- billboard slot
  headline text not null check (char_length(headline) between 3 and 40),
  body text not null check (char_length(body) between 10 and 90),
  cta_label text check (char_length(cta_label) <= 24),
  creative_path text,                                                            -- Storage object, image only; billboards require one
  config jsonb not null default '{}',                                            -- challenge: {"game":"trivia","xmin":8}; rewards below
  reward_xp int not null default 0 check (reward_xp between 0 and 100), reward_coins int not null default 0 check (reward_coins between 0 and 25),
  starts_on date not null, ends_on date not null check (ends_on >= starts_on and ends_on - starts_on < 90),
  status campaign_state not null default 'draft', reject_reason text,
  payment_id uuid references payments, created_by uuid not null references auth.users, created_at timestamptz not null default now(),
  check (placement not in ('sponsored_mission','game_challenge') or reward_xp + reward_coins > 0),
  check (placement <> 'billboard' or (location_id is not null and creative_path is not null)));
alter table business_placements add constraint business_placements_campaign_fk foreign key (campaign_id) references ad_campaigns;
create table campaign_transitions(id bigserial primary key, campaign_id uuid not null references ad_campaigns on delete cascade, from_state campaign_state, to_state campaign_state not null, actor text not null, actor_id uuid, reason text, created_at timestamptz not null default now());

-- Measured events only. Impressions/clicks are written by record_ad_event (deduplicated); mission participation is derived from progress_events/mission_claims.
create table ad_events(id bigserial primary key, campaign_id uuid not null references ad_campaigns, user_id uuid references auth.users, kind text not null check (kind in ('impression','click')),
  bucket timestamptz not null, created_at timestamptz not null default now(), unique (campaign_id, user_id, kind, bucket));       -- 1 impression / 30 min, 1 click / minute per user per campaign

-- ===== State machine, enforced in the database =====
create or replace function can_transition(f campaign_state, t campaign_state, actor text) returns boolean language sql immutable as $$
  select (f, t, actor) in (
    ('draft','submitted','advertiser'), ('submitted','draft','advertiser'), ('submitted','under_review','admin'),
    ('under_review','approved','admin'), ('under_review','rejected','admin'), ('rejected','draft','advertiser'),
    ('approved','active','system'), ('active','paused','advertiser'), ('paused','active','advertiser'),
    ('active','completed','system'), ('paused','completed','system')) $$;
create or replace function campaign_guard() returns trigger language plpgsql as $$
declare actor text := coalesce(current_setting('app.actor', true), 'none');
begin
  if new.status is distinct from old.status then
    if not can_transition(old.status, new.status, actor) then raise exception 'transition % -> % not allowed for %', old.status, new.status, actor; end if;
    insert into campaign_transitions(campaign_id, from_state, to_state, actor, actor_id, reason) values (new.id, old.status, new.status, actor, auth.uid(), new.reject_reason);
  elsif old.status <> 'draft' and (to_jsonb(new) - 'payment_id') is distinct from (to_jsonb(old) - 'payment_id') then raise exception 'only drafts can be edited'; end if;
  return new;
end $$;
create trigger campaign_guard_t before update on ad_campaigns for each row execute function campaign_guard();

-- ===== RLS =====
alter table ad_campaigns enable row level security;
create policy ac_owner on ad_campaigns for select using (exists (select 1 from businesses b where b.id = business_id and b.owner_id = auth.uid()) or is_admin());
create policy ac_insert on ad_campaigns for insert with check (status = 'draft' and created_by = auth.uid() and exists (select 1 from businesses b where b.id = business_id and b.owner_id = auth.uid()));
alter table payments enable row level security;
create policy pay_owner on payments for select using (exists (select 1 from ad_campaigns c join businesses b on b.id = c.business_id where c.payment_id = payments.id and b.owner_id = auth.uid()) or is_admin());
alter table campaign_transitions enable row level security;  create policy ct_read on campaign_transitions for select using (is_admin() or exists (select 1 from ad_campaigns c join businesses b on b.id = c.business_id where c.id = campaign_id and b.owner_id = auth.uid()));
alter table ad_events enable row level security;
revoke all on payments, payment_events, ad_events, campaign_transitions from anon, authenticated;
revoke update, delete on ad_campaigns from anon, authenticated;
grant update (headline, body, cta_label, creative_path, config, reward_xp, reward_coins, starts_on, ends_on) on ad_campaigns to authenticated;   -- content only; status moves via functions

-- ===== Advertiser actions =====
create or replace function advertiser_action(p_id uuid, p_action text) returns void language plpgsql security definer set search_path = public as $$
declare c ad_campaigns; to_s campaign_state;
begin
  select * into c from ad_campaigns where id = p_id and exists (select 1 from businesses b where b.id = business_id and b.owner_id = auth.uid());
  if not found then raise exception 'campaign not found'; end if;
  to_s := case p_action when 'submit' then 'submitted' when 'withdraw' then 'draft' when 'revise' then 'draft' when 'pause' then 'paused' when 'resume' then 'active' end;
  if to_s is null then raise exception 'unknown action'; end if;
  if p_action = 'submit' and c.starts_on < current_date then raise exception 'start date is in the past'; end if;
  perform set_config('app.actor', 'advertiser', true);
  update ad_campaigns set status = to_s where id = p_id;
end $$;

-- ===== Admin actions (manual approval and manual payment confirmation) =====
create or replace function admin_review_campaign(p_id uuid, p_decision text, p_reason text default null) returns void language plpgsql security definer set search_path = public as $$
declare c ad_campaigns;
begin
  if not is_admin() then raise exception 'admin only'; end if;
  select * into c from ad_campaigns where id = p_id for update;
  perform set_config('app.actor', 'admin', true);
  if p_decision = 'start_review' then update ad_campaigns set status = 'under_review' where id = p_id;
  elsif p_decision = 'approve' then
    if not exists (select 1 from businesses where id = c.business_id and status = 'verified' and city_id = c.city_id) then raise exception 'business must be verified in this city'; end if;
    update ad_campaigns set status = 'approved' where id = p_id;
  elsif p_decision = 'reject' then
    if coalesce(p_reason, '') = '' then raise exception 'reason required'; end if;
    update ad_campaigns set status = 'rejected', reject_reason = p_reason where id = p_id;
  else raise exception 'unknown decision'; end if;
  insert into audit_logs(actor_id, action, target_table, target_id, detail) values (auth.uid(), 'review_campaign', 'ad_campaigns', p_id::text, jsonb_build_object('decision', p_decision, 'reason', p_reason));
end $$;
create or replace function admin_confirm_payment(p_campaign uuid, p_reference text, p_amount_minor bigint default null, p_currency text default null) returns void language plpgsql security definer set search_path = public as $$
declare pid uuid;
begin
  if not is_admin() then raise exception 'admin only'; end if;
  if coalesce(p_reference, '') = '' then raise exception 'payment reference required'; end if;
  insert into payments(provider, status, amount_minor, currency, reference, confirmed_by, confirmed_at) values ('manual', 'confirmed', p_amount_minor, p_currency, p_reference, auth.uid(), now()) returning id into pid;
  update ad_campaigns set payment_id = pid where id = p_campaign and status in ('approved','active','paused');
  insert into payment_events(payment_id, kind, payload) values (pid, 'manual_confirmation', jsonb_build_object('campaign', p_campaign));
  insert into audit_logs(actor_id, action, target_table, target_id, detail) values (auth.uid(), 'confirm_payment', 'ad_campaigns', p_campaign::text, jsonb_build_object('reference', p_reference));
end $$;

-- ===== Scheduler (pg_cron every 5 minutes): approved + paid + start date reached -> active; past end date -> completed =====
create or replace function advance_campaigns() returns void language plpgsql security definer set search_path = public as $$
begin
  perform set_config('app.actor', 'system', true);
  update ad_campaigns c set status = 'active' where status = 'approved' and starts_on <= current_date and ends_on >= current_date
    and exists (select 1 from payments p where p.id = c.payment_id and p.status = 'confirmed');
  update ad_campaigns set status = 'completed' where status in ('active','paused') and ends_on < current_date;
end $$;
-- select cron.schedule('advance-campaigns', '*/5 * * * *', 'select advance_campaigns()');

-- ===== Tracking: deduplicated, only for active campaigns =====
create or replace function record_ad_event(p_campaign uuid, p_kind text) returns void language plpgsql security definer set search_path = public as $$
declare w interval := case p_kind when 'impression' then interval '30 minutes' else interval '1 minute' end;
begin
  if not exists (select 1 from ad_campaigns where id = p_campaign and status = 'active' and current_date between starts_on and ends_on) then return; end if;
  insert into ad_events(campaign_id, user_id, kind, bucket) values (p_campaign, auth.uid(), p_kind, to_timestamp(floor(extract(epoch from now()) / extract(epoch from w)) * extract(epoch from w)))
  on conflict do nothing;
end $$;
grant execute on function advertiser_action, admin_review_campaign, admin_confirm_payment, record_ad_event to authenticated;

-- ===== Read models =====
-- Public: only ACTIVE campaigns, no payment info.
create view active_ads with (security_invoker = false) as
  select c.id, c.city_id, c.placement, c.location_id, c.headline, c.body, c.cta_label, c.creative_path, c.config, c.reward_xp, c.reward_coins, c.starts_on, c.ends_on, b.id as business_id, b.name as business_name
  from ad_campaigns c join businesses b on b.id = c.business_id where c.status = 'active' and current_date between c.starts_on and c.ends_on;
grant select on active_ads to anon, authenticated;
-- Advertiser: aggregate counts only (no user-level data), and only once a campaign has been approved.
create view campaign_metrics with (security_invoker = false) as
  select c.id as campaign_id,
         count(*) filter (where e.kind = 'impression') as impressions, count(*) filter (where e.kind = 'click') as clicks,
         (select count(distinct pe.user_id) from progress_events pe where c.placement in ('sponsored_mission','game_challenge') and pe.created_at::date between c.starts_on and c.ends_on
            and ((c.placement = 'sponsored_mission' and pe.type = 'checkin' and pe.ref = c.location_id::text) or (c.placement = 'game_challenge' and pe.type = 'game' and pe.ref = c.config->>'game'))) as mission_participants
  from ad_campaigns c left join ad_events e on e.campaign_id = c.id
  where c.status in ('approved','active','paused','completed') and (is_admin() or exists (select 1 from businesses b where b.id = c.business_id and b.owner_id = auth.uid()))
  group by c.id;
grant select on campaign_metrics to authenticated;
