-- Lifemindwurld businesses: multi-city listings, admin review, in-city placements and sponsored campaigns.
-- Assumes cities(id text pk), districts, world_locations(id, city_id, ...) and profiles(id, username, avatar) already exist.
-- Nothing here contains real business data. Businesses enter only through registration and become public only after admin review.

create type business_category as enum ('restaurants','shopping','entertainment','hotels','education','healthcare','services','events','tourism','businesses');
create type business_status   as enum ('pending','verified','rejected','suspended');

-- Admins live in their own table (never a column a user could update on their profile).
create table admin_users(user_id uuid primary key references auth.users on delete cascade);
create or replace function is_admin() returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from admin_users where user_id = auth.uid()) $$;

create table businesses(
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users on delete cascade,
  city_id text not null references cities(id),                      -- a business belongs to ONE city; chains register per city
  slug text not null,
  name text not null check (char_length(name) between 2 and 60),
  category business_category not null,
  description text not null check (char_length(description) between 20 and 400),
  address_text text not null check (char_length(address_text) between 3 and 120),
  website text check (website is null or website ~* '^https://[^\s<>"'']+$'),
  contact_email text check (contact_email is null or contact_email ~ '^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$'),
  contact_phone text check (contact_phone is null or contact_phone ~ '^[+0-9 ()-]{6,20}$'),
  hours text check (char_length(hours) <= 200),
  logo_path text,                                                    -- Storage path, set only after verification
  status business_status not null default 'pending',
  verified_at timestamptz, verified_by uuid references auth.users, review_note text,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
  unique (city_id, slug),
  check (contact_email is not null or contact_phone is not null),
  check (status <> 'verified' or (verified_at is not null and verified_by is not null)));
create index businesses_browse on businesses (city_id, category) where status = 'verified';
alter table businesses add column search tsvector generated always as
  (to_tsvector('simple', coalesce(name,'') || ' ' || coalesce(description,'') || ' ' || category::text)) stored;
create index businesses_search on businesses using gin (search);

create table business_featured(
  id bigserial primary key, business_id uuid not null references businesses on delete cascade,
  title text not null check (char_length(title) <= 40), body text not null check (char_length(body) <= 160), sort int not null default 0);

-- Ads: campaigns need approval; placements put a verified business onto a virtual location.
create table ad_campaigns(
  id uuid primary key default gen_random_uuid(), business_id uuid not null references businesses on delete cascade,
  name text not null, sponsored boolean not null default true,
  status text not null default 'pending' check (status in ('pending','approved','rejected','ended')),
  starts_at timestamptz, ends_at timestamptz, approved_by uuid references auth.users, approved_at timestamptz);
create table business_placements(
  id uuid primary key default gen_random_uuid(),
  business_id uuid not null references businesses on delete cascade,
  location_id uuid not null references world_locations,
  kind text not null check (kind in ('storefront','marker','billboard')),
  campaign_id uuid references ad_campaigns,                           -- required for sponsored placements and billboards
  starts_at timestamptz not null default now(), ends_at timestamptz,
  check (kind = 'storefront' or kind = 'marker' or campaign_id is not null));
create unique index one_active_slot on business_placements (location_id) where ends_at is null;

create or replace function placement_guard() returns trigger language plpgsql as $$
begin
  if not exists (select 1 from businesses b join world_locations l on l.city_id = b.city_id
                 where b.id = new.business_id and b.status = 'verified' and l.id = new.location_id) then
    raise exception 'only verified businesses may be placed, and only in their own city'; end if;
  if new.campaign_id is not null and not exists (select 1 from ad_campaigns c where c.id = new.campaign_id and c.business_id = new.business_id and c.status = 'approved') then
    raise exception 'campaign is not approved'; end if;
  return new; end $$;
create trigger placement_guard_t before insert or update on business_placements for each row execute function placement_guard();

create table audit_logs(id bigserial primary key, actor_id uuid, action text not null, target_table text, target_id text, detail jsonb, created_at timestamptz not null default now());
create or replace function audit_immutable() returns trigger language plpgsql as $$ begin raise exception 'audit_logs is append-only'; end $$;
create trigger audit_no_change before update or delete on audit_logs for each row execute function audit_immutable();

-- ===== Row Level Security =====
alter table businesses enable row level security;
create policy biz_public_read on businesses for select using (status = 'verified');
create policy biz_owner_read  on businesses for select using (owner_id = auth.uid());
create policy biz_owner_insert on businesses for insert with check (owner_id = auth.uid() and status = 'pending' and verified_at is null and verified_by is null);
create policy biz_owner_update on businesses for update using (owner_id = auth.uid()) with check (owner_id = auth.uid());
create policy biz_admin_all on businesses for all using (is_admin()) with check (is_admin());
revoke update on businesses from authenticated;                       -- owners may change descriptive fields only (below); status/verification are never writable by them
grant update (name, description, address_text, website, contact_email, contact_phone, hours) on businesses to authenticated;
create or replace function reset_review_on_edit() returns trigger language plpgsql security definer as $$
begin if not is_admin() and new.status = 'verified' then new.status := 'pending'; new.verified_at := null; new.verified_by := null; end if; return new; end $$;
create trigger reset_review before update on businesses for each row execute function reset_review_on_edit();   -- edits to a verified listing are re-reviewed

alter table business_featured enable row level security;
create policy bf_read on business_featured for select using (exists (select 1 from businesses b where b.id = business_id and (b.status = 'verified' or b.owner_id = auth.uid())));
create policy bf_owner_write on business_featured for all using (exists (select 1 from businesses b where b.id = business_id and b.owner_id = auth.uid()))
  with check (exists (select 1 from businesses b where b.id = business_id and b.owner_id = auth.uid()));
alter table ad_campaigns enable row level security;
create policy ac_owner_read on ad_campaigns for select using (exists (select 1 from businesses b where b.id = business_id and b.owner_id = auth.uid()) or is_admin());
create policy ac_owner_insert on ad_campaigns for insert with check (status = 'pending' and approved_by is null and exists (select 1 from businesses b where b.id = business_id and b.owner_id = auth.uid() and b.status = 'verified'));
create policy ac_admin_all on ad_campaigns for all using (is_admin()) with check (is_admin());
alter table business_placements enable row level security;
create policy bp_read on business_placements for select using (ends_at is null or ends_at > now());
create policy bp_admin_all on business_placements for all using (is_admin()) with check (is_admin());
alter table audit_logs enable row level security;
create policy al_admin_read on audit_logs for select using (is_admin());

-- ===== Admin review (the ONLY way a business becomes verified) =====
create or replace function review_business(p_id uuid, p_decision text, p_note text default null) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not is_admin() then raise exception 'admin only'; end if;
  if p_decision not in ('verified','rejected','suspended') then raise exception 'bad decision'; end if;
  update businesses set status = p_decision::business_status, review_note = p_note, updated_at = now(),
         verified_at = case when p_decision = 'verified' then now() end, verified_by = case when p_decision = 'verified' then auth.uid() end
  where id = p_id;
  insert into audit_logs(actor_id, action, target_table, target_id, detail) values (auth.uid(), 'review_business', 'businesses', p_id::text, jsonb_build_object('decision', p_decision, 'note', p_note));
end $$;
grant execute on function review_business to authenticated;           -- still fails unless is_admin()

-- ===== Public read model for Discover and the city (no owner ids, no review notes, no emails of unverified listings) =====
create view public_businesses with (security_invoker = false) as
  select b.id, b.city_id, b.name, b.slug, b.category, b.description, b.address_text, b.website, b.contact_email, b.contact_phone, b.hours, b.logo_path, b.search,
         p.location_id, p.kind as placement_kind, (c.id is not null and c.sponsored) as sponsored,
         coalesce((select jsonb_agg(jsonb_build_object('title', f.title, 'body', f.body) order by f.sort) from business_featured f where f.business_id = b.id), '[]') as featured
  from businesses b
  left join business_placements p on p.business_id = b.id and (p.ends_at is null or p.ends_at > now())
  left join ad_campaigns c on c.id = p.campaign_id and c.status = 'approved' and now() between c.starts_at and coalesce(c.ends_at, 'infinity')
  where b.status = 'verified';
grant select on public_businesses to anon, authenticated;
-- Discover query: select * from public_businesses where city_id = $1 and ($2::business_category is null or category = $2) and search @@ plainto_tsquery('simple', $3) order by sponsored desc, name;
-- Adding London, Nairobi, ...: insert a row into cities and world_locations. Businesses, placements and the views work unchanged.
