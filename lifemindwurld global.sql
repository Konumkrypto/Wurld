-- Lifemindwurld global city platform: World > Country > City > District > Location, one shared engine, many cities.
-- Run this FIRST. A city is added with DATA ONLY (rows below); no application code per city.
-- A city can only be set to 'live' through publish_city(), which re-checks the same launch thresholds the client uses.
-- NOTE: the client uses short text location ids ("fq2", "ldn_cl1"). The earlier progression/business/advertising SQL files declared
-- location ids as uuid: change those references to text (or compare with id::text) when you wire everything together.

create type city_status as enum ('coming_soon','live');

create table countries(id char(2) primary key, name text not null, flag text);
create table cities(
  id text primary key check (id ~ '^[a-z][a-z0-9_]{1,23}$'),
  country_id char(2) not null references countries(id),
  name text not null,
  timezone text not null,                                       -- IANA name; drives daily mission resets, daily caps and campaign dates
  default_language text not null, currency char(3) not null,    -- currency of the city's advertising inventory
  center_lat numeric(8,5), center_lng numeric(8,5),             -- city centre only, never a user position
  status city_status not null default 'coming_soon', published_at timestamptz, created_at timestamptz not null default now());
create or replace function check_timezone() returns trigger language plpgsql as $$
begin if not exists (select 1 from pg_timezone_names where name = new.timezone) then raise exception 'unknown timezone %', new.timezone; end if; return new; end $$;
create trigger cities_tz before insert or update of timezone on cities for each row execute function check_timezone();
create or replace function city_today(p_city text) returns date language sql stable as $$
  select (now() at time zone timezone)::date from cities where id = p_city $$;   -- use instead of current_date in daily/ad logic

create table city_languages(city_id text not null references cities on delete cascade, code text not null, name text not null,
  interface_available boolean not null default false, content_available boolean not null default false, primary key (city_id, code));

-- Each city has its OWN map; the engine renders any map in this shape.
create table city_maps(city_id text primary key references cities on delete cascade, size int not null check (size between 8 and 64), terrain jsonb not null, spawn_x int not null, spawn_y int not null);
create table districts(id text primary key, city_id text not null references cities on delete cascade, name text not null, center_x int not null, center_y int not null);   -- ids are globally unique (prefix them: 'ldn_', 'tyo_')
create table world_locations(
  id text primary key, city_id text not null references cities on delete cascade, district_id text not null references districts,
  name text not null, category text not null, interaction text not null default 'info' check (interaction in ('info','game','mission','business')),
  x int not null, y int not null, visual jsonb not null default '{}', config jsonb not null default '{}',   -- config: {"game":"trivia"} | {"billboard":true} | {"walk":true} ...
  unique (city_id, x, y));
create index loc_city on world_locations (city_id, category);
create table city_events(id uuid primary key default gen_random_uuid(), city_id text not null references cities on delete cascade, title text not null check (char_length(title) <= 80),
  starts_at timestamptz not null, ends_at timestamptz not null, location_id text references world_locations, status text not null default 'draft' check (status in ('draft','published','cancelled')), check (ends_at > starts_at));
create table city_local_content(id uuid primary key default gen_random_uuid(), city_id text not null references cities on delete cascade, kind text not null check (kind in ('trivia','tip','feed')),
  language text not null default 'en', payload jsonb not null, status text not null default 'draft' check (status in ('draft','published')));
create table city_ad_settings(city_id text primary key references cities on delete cascade, billboard_rotation int not null default 4, featured_listings int not null default 3, sponsored_missions int not null default 3);
create view city_ad_inventory as select l.city_id, l.id as slot_id, c.currency from world_locations l join cities c on c.id = l.city_id where (l.config->>'billboard')::boolean;

-- Launch policy is data, so it can change without a release.
create table launch_thresholds(singleton boolean primary key default true check (singleton), districts int not null default 4, locations int not null default 12,
  landmarks int not null default 5, trivia int not null default 10, hunt_targets int not null default 5, games text[] not null default '{trivia,memory,hunt}');
insert into launch_thresholds default values;

create view city_readiness as
  select c.id as city_id, c.status,
    exists (select 1 from city_maps m where m.city_id = c.id) as has_map,
    (select count(*) from districts d where d.city_id = c.id) as districts,
    (select count(*) from world_locations l where l.city_id = c.id) as locations,
    (select count(*) from world_locations l where l.city_id = c.id and l.category = 'landmark') as landmarks,
    (select count(*) from city_local_content t where t.city_id = c.id and t.kind = 'trivia' and t.status = 'published') as local_trivia,
    (select count(distinct l.config->>'game') from world_locations l where l.city_id = c.id and l.interaction = 'game' and l.config->>'game' = any ((select games from launch_thresholds))) as game_types,
    (select count(*) from world_locations l where l.city_id = c.id and l.interaction not in ('mission','game')) as hunt_targets,
    (select count(*) from world_locations l where l.city_id = c.id and l.interaction = 'mission') as mission_markers,
    exists (select 1 from city_languages g where g.city_id = c.id and g.interface_available) as has_language,
    (select count(*) from businesses b where b.city_id = c.id and b.status = 'verified') as businesses,       -- optional
    (select count(*) from city_events e where e.city_id = c.id and e.status = 'published') as events,         -- optional
    (select count(*) from city_ad_inventory i where i.city_id = c.id) as ad_slots                            -- optional
  from cities c;

create or replace function publish_city(p_city text) returns void language plpgsql security definer set search_path = public as $$
declare r city_readiness; t launch_thresholds; missing text[] := '{}';
begin
  if not is_admin() then raise exception 'admin only'; end if;
  select * into r from city_readiness where city_id = p_city; select * into t from launch_thresholds;
  if not r.has_map then missing := missing || 'unique map'; end if;
  if r.districts < t.districts then missing := missing || 'districts'; end if;
  if r.locations < t.locations then missing := missing || 'locations'; end if;
  if r.landmarks < t.landmarks then missing := missing || 'landmarks'; end if;
  if r.game_types < cardinality(t.games) then missing := missing || 'game locations'; end if;
  if r.hunt_targets < t.hunt_targets then missing := missing || 'scavenger-hunt targets'; end if;
  if r.mission_markers < 2 then missing := missing || 'mission markers'; end if;
  if not r.has_language then missing := missing || 'language settings'; end if;
  if cardinality(missing) > 0 then raise exception 'city not ready, missing: %', array_to_string(missing, ', '); end if;
  update cities set status = 'live', published_at = now() where id = p_city;
  insert into audit_logs(actor_id, action, target_table, target_id) values (auth.uid(), 'publish_city', 'cities', p_city);
end $$;
create or replace function unpublish_city(p_city text) returns void language plpgsql security definer set search_path = public as $$
begin if not is_admin() then raise exception 'admin only'; end if; update cities set status = 'coming_soon' where id = p_city;
  insert into audit_logs(actor_id, action, target_table, target_id) values (auth.uid(), 'unpublish_city', 'cities', p_city); end $$;
grant execute on function publish_city, unpublish_city to authenticated;      -- fail unless is_admin()

-- RLS: the city directory is public (so the selector can show COMING SOON); city CONTENT is readable only for live cities.
alter table countries enable row level security;   create policy c_read on countries for select using (true);
alter table cities enable row level security;      create policy ci_read on cities for select using (true);
alter table city_languages enable row level security; create policy cl_read on city_languages for select using (true);
alter table city_maps enable row level security;   create policy cm_read on city_maps for select using (exists (select 1 from cities c where c.id = city_id and c.status = 'live') or is_admin());
alter table districts enable row level security;   create policy d_read on districts for select using (exists (select 1 from cities c where c.id = city_id and c.status = 'live') or is_admin());
alter table world_locations enable row level security; create policy wl_read on world_locations for select using (exists (select 1 from cities c where c.id = city_id and c.status = 'live') or is_admin());
alter table city_events enable row level security; create policy ce_read on city_events for select using (status = 'published' and exists (select 1 from cities c where c.id = city_id and c.status = 'live'));
alter table city_local_content enable row level security; create policy lc_read on city_local_content for select using (status = 'published' and exists (select 1 from cities c where c.id = city_id and c.status = 'live'));
alter table city_ad_settings enable row level security; create policy as_read on city_ad_settings for select using (true);
alter table launch_thresholds enable row level security; create policy lt_read on launch_thresholds for select using (true);
revoke insert, update, delete on countries, cities, city_languages, city_maps, districts, world_locations, city_events, city_local_content, city_ad_settings, launch_thresholds from anon, authenticated;  -- content is imported by admins/migrations

-- Seed: facts only. All cities start as COMING SOON; Lagos is switched on with publish_city('lagos') after its content rows are imported.
insert into countries values ('NG','Nigeria','🇳🇬'),('GB','United Kingdom','🇬🇧'),('US','United States','🇺🇸'),('KE','Kenya','🇰🇪'),('GH','Ghana','🇬🇭'),('FR','France','🇫🇷'),('DE','Germany','🇩🇪'),('EE','Estonia','🇪🇪'),('AE','United Arab Emirates','🇦🇪'),('JP','Japan','🇯🇵');
insert into cities(id, country_id, name, timezone, default_language, currency, center_lat, center_lng) values
 ('lagos','NG','Lagos','Africa/Lagos','en','NGN',6.52440,3.37920),('london','GB','London','Europe/London','en','GBP',51.50740,-0.12780),
 ('ny','US','New York','America/New_York','en','USD',40.71280,-74.00600),('nairobi','KE','Nairobi','Africa/Nairobi','en','KES',-1.29210,36.82190),
 ('accra','GH','Accra','Africa/Accra','en','GHS',5.60370,-0.18700),('paris','FR','Paris','Europe/Paris','fr','EUR',48.85660,2.35220),
 ('berlin','DE','Berlin','Europe/Berlin','de','EUR',52.52000,13.40500),('tallinn','EE','Tallinn','Europe/Tallinn','et','EUR',59.43700,24.75360),
 ('dubai','AE','Dubai','Asia/Dubai','ar','AED',25.20480,55.27080),('tokyo','JP','Tokyo','Asia/Tokyo','ja','JPY',35.67620,139.65030);
insert into city_languages(city_id, code, name, interface_available, content_available) values
 ('lagos','en','English',true,true),('london','en','English',true,false),('ny','en','English',true,false),('nairobi','en','English',true,false),('nairobi','sw','Kiswahili',false,false),
 ('accra','en','English',true,false),('paris','fr','Français',false,false),('berlin','de','Deutsch',false,false),('tallinn','et','Eesti',false,false),('dubai','ar','العربية',false,false),('tokyo','ja','日本語',false,false);
-- To add a city: insert cities, city_languages, city_maps, districts, world_locations, content rows, then select publish_city('<id>').
