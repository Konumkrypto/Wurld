-- Lifemindwurld social: friends, community posts, comments, reactions, reports, blocks, moderation.
-- Assumes profiles(id, username, avatar jsonb, interests text[], city_id), cities(id), player_balances (progression SQL), is_admin() (businesses SQL).
-- Design rules: no email, no exact location, no presence, no private/anonymous chat. Clients READ through RLS and WRITE only through the functions below.

alter table profiles add column if not exists accept_requests text not null default 'everyone' check (accept_requests in ('everyone','nobody'));

create table friendships(
  id uuid primary key default gen_random_uuid(),
  user_a uuid not null references auth.users on delete cascade, user_b uuid not null references auth.users on delete cascade,   -- stored as (least, greatest): one row per pair
  requester uuid not null, status text not null default 'pending' check (status in ('pending','accepted','rejected')),
  created_at timestamptz not null default now(), responded_at timestamptz,
  check (user_a < user_b), check (requester in (user_a, user_b)), unique (user_a, user_b));
create table blocks(blocker uuid not null references auth.users on delete cascade, blocked uuid not null references auth.users on delete cascade,
  created_at timestamptz not null default now(), primary key (blocker, blocked), check (blocker <> blocked));
create table community_members(user_id uuid not null references auth.users on delete cascade, city_id text not null references cities(id), joined_at timestamptz not null default now(), primary key (user_id, city_id));

create type content_status as enum ('visible','hidden','removed','deleted');
create table posts(id uuid primary key default gen_random_uuid(), author_id uuid not null references auth.users on delete cascade, city_id text not null references cities(id),
  body text not null check (char_length(body) between 1 and 280 and body !~* 'https?:|www\.|@\w|\d[\d\s().-]{7,}\d'),
  status content_status not null default 'visible', created_at timestamptz not null default now());
create index posts_feed on posts (city_id, created_at desc) where status = 'visible';
create table comments(id uuid primary key default gen_random_uuid(), post_id uuid not null references posts on delete cascade, author_id uuid not null references auth.users on delete cascade,
  body text not null check (char_length(body) between 1 and 140 and body !~* 'https?:|www\.|@\w|\d[\d\s().-]{7,}\d'),
  status content_status not null default 'visible', created_at timestamptz not null default now());
create table reactions(post_id uuid not null references posts on delete cascade, user_id uuid not null references auth.users on delete cascade,
  emoji text not null check (emoji in ('👍','❤','😂','🎉')), primary key (post_id, user_id));          -- one reaction per user per post

create table reports(id uuid primary key default gen_random_uuid(), reporter_id uuid not null references auth.users on delete cascade,
  target_type text not null check (target_type in ('user','post','comment')), target_id uuid not null, target_user uuid not null,
  reason text not null check (reason in ('spam','harassment','hate','inappropriate','scam','other')), note text check (char_length(note) <= 200),
  status text not null default 'open' check (status in ('open','actioned','dismissed')), created_at timestamptz not null default now());
create unique index one_open_report on reports (reporter_id, target_type, target_id) where status = 'open';   -- no duplicate reports
create table user_restrictions(user_id uuid primary key references auth.users on delete cascade, muted_until timestamptz, suspended boolean not null default false, reason text, set_by uuid, set_at timestamptz not null default now());
create table moderation_actions(id bigserial primary key, actor_id uuid, action text not null, target_type text, target_id text, detail jsonb, created_at timestamptz not null default now());
create or replace function mod_log_immutable() returns trigger language plpgsql as $$ begin raise exception 'moderation_actions is append-only'; end $$;
create trigger mod_log_lock before update or delete on moderation_actions for each row execute function mod_log_immutable();

-- ===== helpers =====
create or replace function is_blocked(a uuid, b uuid) returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from blocks where (blocker = a and blocked = b) or (blocker = b and blocked = a)) $$;
create or replace function can_participate(u uuid) returns boolean language sql stable security definer set search_path = public as $$
  select not exists (select 1 from user_restrictions r where r.user_id = u and (r.suspended or r.muted_until > now())) $$;
create or replace function uid_of(p_username text) returns uuid language sql stable security definer set search_path = public as $$ select id from profiles where username = p_username $$;

-- ===== RLS: read what you may see; no direct writes =====
alter table friendships enable row level security;        create policy fr_own on friendships for select using (auth.uid() in (user_a, user_b));
alter table blocks enable row level security;             create policy bl_own on blocks for select using (blocker = auth.uid());
alter table community_members enable row level security;  create policy cm_own on community_members for select using (user_id = auth.uid());
alter table posts enable row level security;
create policy posts_read on posts for select using (auth.uid() is not null and (status = 'visible' and not is_blocked(auth.uid(), author_id) or author_id = auth.uid()));   -- sign-in required to read
alter table comments enable row level security;
create policy comments_read on comments for select using (auth.uid() is not null and status = 'visible' and not is_blocked(auth.uid(), author_id));
alter table reactions enable row level security;          create policy rx_read on reactions for select using (auth.uid() is not null);
alter table reports enable row level security;            create policy rep_own on reports for select using (reporter_id = auth.uid() or is_admin());
alter table user_restrictions enable row level security;  create policy ur_admin on user_restrictions for select using (is_admin());
alter table moderation_actions enable row level security; create policy ma_admin on moderation_actions for select using (is_admin());
revoke insert, update, delete, truncate on friendships, blocks, community_members, posts, comments, reactions, reports, user_restrictions, moderation_actions from anon, authenticated;

-- ===== Public profile: the ONLY profile data other players can read (no id, email, location or presence) =====
create view public_profiles with (security_invoker = false) as
  select p.username, p.avatar, p.city_id, p.interests, coalesce(b.level, 1) as level, coalesce(b.xp, 0) as xp
  from profiles p left join player_balances b on b.user_id = p.id
  where not is_blocked(auth.uid(), p.id);
grant select on public_profiles to authenticated;

-- ===== Friends =====
create or replace function send_friend_request(p_username text) returns void language plpgsql security definer set search_path = public as $$
declare me uuid := auth.uid(); them uuid := uid_of(p_username); f friendships;
begin
  if me is null or them is null or them = me then raise exception 'player not found'; end if;
  if not can_participate(me) then raise exception 'restricted'; end if;
  if is_blocked(me, them) then raise exception 'not allowed'; end if;
  if (select accept_requests from profiles where id = them) = 'nobody' then raise exception 'not accepting requests'; end if;
  if (select count(*) from friendships where requester = me and status = 'pending') >= 20 then raise exception 'too many pending requests'; end if;
  select * into f from friendships where user_a = least(me, them) and user_b = greatest(me, them);
  if found and (f.status <> 'rejected' or f.responded_at > now() - interval '7 days') then raise exception 'request exists or was declined recently'; end if;
  delete from friendships where id = f.id;
  insert into friendships(user_a, user_b, requester) values (least(me, them), greatest(me, them), me);
end $$;
create or replace function respond_friend_request(p_id uuid, p_accept boolean) returns void language sql security definer set search_path = public as $$
  update friendships set status = case when p_accept then 'accepted' else 'rejected' end, responded_at = now()
  where id = p_id and status = 'pending' and requester <> auth.uid() and auth.uid() in (user_a, user_b) $$;      -- only the recipient can respond
create or replace function cancel_or_remove_friend(p_id uuid) returns void language sql security definer set search_path = public as $$
  delete from friendships where id = p_id and auth.uid() in (user_a, user_b) and (status = 'accepted' or (status = 'pending' and requester = auth.uid())) $$;
create or replace function block_user(p_username text) returns void language plpgsql security definer set search_path = public as $$
declare me uuid := auth.uid(); them uuid := uid_of(p_username);
begin
  if them is null or them = me then raise exception 'player not found'; end if;
  insert into blocks(blocker, blocked) values (me, them) on conflict do nothing;
  delete from friendships where user_a = least(me, them) and user_b = greatest(me, them);
end $$;
create or replace function unblock_user(p_username text) returns void language sql security definer set search_path = public as $$
  delete from blocks where blocker = auth.uid() and blocked = uid_of(p_username) $$;

-- ===== Community =====
create or replace function join_community(p_city text) returns void language sql security definer set search_path = public as $$
  insert into community_members(user_id, city_id) select auth.uid(), id from cities where id = p_city and can_participate(auth.uid()) on conflict do nothing $$;
create or replace function create_post(p_city text, p_body text) returns uuid language plpgsql security definer set search_path = public as $$
declare me uuid := auth.uid(); pid uuid;
begin
  if not can_participate(me) then raise exception 'restricted'; end if;
  if not exists (select 1 from community_members where user_id = me and city_id = p_city) then raise exception 'join the community first'; end if;
  if (select count(*) from posts where author_id = me and created_at > now() - interval '1 hour') >= 5 then raise exception 'rate limit: 5 posts per hour'; end if;
  if (select count(*) from posts where author_id = me and created_at > now() - interval '1 day') >= 20 then raise exception 'daily post limit'; end if;
  if exists (select 1 from posts where author_id = me and body = p_body and created_at > now() - interval '10 minutes') then raise exception 'duplicate post'; end if;
  insert into posts(author_id, city_id, body) values (me, p_city, p_body) returning id into pid;     -- CHECK constraint blocks links / @mentions / phone numbers
  return pid;
end $$;
create or replace function add_comment(p_post uuid, p_body text) returns void language plpgsql security definer set search_path = public as $$
declare me uuid := auth.uid(); po posts;
begin
  select * into po from posts where id = p_post and status = 'visible';
  if not found or is_blocked(me, po.author_id) or not can_participate(me) then raise exception 'not allowed'; end if;
  if not exists (select 1 from community_members where user_id = me and city_id = po.city_id) then raise exception 'join the community first'; end if;
  if (select count(*) from comments where author_id = me and created_at > now() - interval '1 hour') >= 20 then raise exception 'rate limit: 20 comments per hour'; end if;
  insert into comments(post_id, author_id, body) values (p_post, me, p_body);
end $$;
create or replace function set_reaction(p_post uuid, p_emoji text) returns void language plpgsql security definer set search_path = public as $$
declare me uuid := auth.uid();
begin
  if not exists (select 1 from posts where id = p_post and status = 'visible' and not is_blocked(me, author_id)) then raise exception 'not allowed'; end if;
  if exists (select 1 from reactions where post_id = p_post and user_id = me and emoji = p_emoji) then delete from reactions where post_id = p_post and user_id = me;
  else insert into reactions values (p_post, me, p_emoji) on conflict (post_id, user_id) do update set emoji = excluded.emoji; end if;
end $$;
create or replace function delete_own_content(p_type text, p_id uuid) returns void language plpgsql security definer set search_path = public as $$
begin
  if p_type = 'post' then update posts set status = 'deleted' where id = p_id and author_id = auth.uid();
  else update comments set status = 'deleted' where id = p_id and author_id = auth.uid(); end if;
end $$;

-- ===== Reports and moderation =====
create or replace function report_content(p_type text, p_id uuid, p_reason text, p_note text default null) returns void language plpgsql security definer set search_path = public as $$
declare me uuid := auth.uid(); tgt uuid;
begin
  tgt := case p_type when 'post' then (select author_id from posts where id = p_id) when 'comment' then (select author_id from comments where id = p_id) when 'user' then p_id end;
  if tgt is null or tgt = me then raise exception 'cannot report this'; end if;
  if (select count(*) from reports where reporter_id = me and created_at > now() - interval '1 day') >= 10 then raise exception 'daily report limit'; end if;
  insert into reports(reporter_id, target_type, target_id, target_user, reason, note) values (me, p_type, p_id, tgt, p_reason, p_note);   -- unique index blocks duplicates
  if p_type in ('post','comment') and (select count(distinct reporter_id) from reports where target_type = p_type and target_id = p_id and status = 'open') >= 3 then
    if p_type = 'post' then update posts set status = 'hidden' where id = p_id and status = 'visible'; else update comments set status = 'hidden' where id = p_id and status = 'visible'; end if;
    insert into moderation_actions(actor_id, action, target_type, target_id, detail) values (null, 'auto_hide', p_type, p_id::text, '{"reason":"3 distinct reports"}');
  end if;
end $$;
create or replace function admin_moderate(p_action text, p_type text, p_id uuid, p_note text default null) returns void language plpgsql security definer set search_path = public as $$
begin
  if not is_admin() then raise exception 'admin only'; end if;
  if p_action in ('hide','remove','restore') and p_type = 'post' then update posts set status = (case p_action when 'hide' then 'hidden' when 'remove' then 'removed' else 'visible' end)::content_status where id = p_id;
  elsif p_action in ('hide','remove','restore') and p_type = 'comment' then update comments set status = (case p_action when 'hide' then 'hidden' when 'remove' then 'removed' else 'visible' end)::content_status where id = p_id;
  elsif p_action = 'mute_24h' then insert into user_restrictions(user_id, muted_until, set_by, reason) values (p_id, now() + interval '24 hours', auth.uid(), p_note) on conflict (user_id) do update set muted_until = excluded.muted_until, set_by = auth.uid(), reason = p_note, set_at = now();
  elsif p_action = 'suspend' then insert into user_restrictions(user_id, suspended, set_by, reason) values (p_id, true, auth.uid(), p_note) on conflict (user_id) do update set suspended = true, set_by = auth.uid(), reason = p_note, set_at = now();
  elsif p_action = 'lift' then delete from user_restrictions where user_id = p_id;
  elsif p_action <> 'dismiss' then raise exception 'unknown action'; end if;
  if p_action <> 'restore' and p_action <> 'lift' then update reports set status = case when p_action = 'dismiss' then 'dismissed' else 'actioned' end where target_id = p_id and status = 'open'; end if;
  insert into moderation_actions(actor_id, action, target_type, target_id, detail) values (auth.uid(), p_action, p_type, p_id::text, jsonb_build_object('note', p_note));
end $$;
grant execute on function send_friend_request, respond_friend_request, cancel_or_remove_friend, block_user, unblock_user, join_community, create_post, add_comment,
  set_reaction, delete_own_content, report_content, admin_moderate to authenticated;   -- admin_moderate still fails unless is_admin()
