-- ============================================================
-- Supabase 初始化 SQL（把整个文件粘贴到 Supabase SQL Editor 执行）
-- 对应网页：GitHub Pages 版个人主页（留言板 + 在线客服 + 社区聊天室）
-- 管理口令：xm7K92qz（可在下方 _ADMIN_SECRET_ 处统一修改）
-- ============================================================

-- ---------- 1. 留言板 ----------
create table if not exists guestbook_messages (
  id bigint generated always as identity primary key,
  name text,
  contact text,
  content text not null,
  status text not null default 'pending',
  created_at timestamptz not null default now()
);
alter table guestbook_messages enable row level security;
drop policy if exists "gb insert" on guestbook_messages;
create policy "gb insert" on guestbook_messages for insert to anon, authenticated with check (true);
drop policy if exists "gb read approved" on guestbook_messages;
create policy "gb read approved" on guestbook_messages for select to anon, authenticated using (status = 'approved');

-- ---------- 2. 匿名在线客服聊天 ----------
create table if not exists chat_messages (
  id bigint generated always as identity primary key,
  conv_id text not null,
  sender text not null,
  sender_name text,
  content text,
  image text,
  created_at timestamptz not null default now()
);
alter table chat_messages enable row level security;
-- 不创建任何策略：全部读写走下面的 SECURITY DEFINER 函数

-- ---------- 3. 社区聊天室：用户资料 ----------
create table if not exists chat_profiles (
  id uuid primary key default auth.uid(),
  nickname text not null,
  last_seen timestamptz not null default now(),
  created_at timestamptz not null default now()
);
alter table chat_profiles enable row level security;
drop policy if exists "cp read" on chat_profiles;
create policy "cp read" on chat_profiles for select to authenticated using (true);
drop policy if exists "cp insert" on chat_profiles;
create policy "cp insert" on chat_profiles for insert to authenticated with check (id = auth.uid());
drop policy if exists "cp update" on chat_profiles;
create policy "cp update" on chat_profiles for update to authenticated using (id = auth.uid()) with check (id = auth.uid());

-- ---------- 4. 社区聊天室：群聊 ----------
create table if not exists chat_group_messages (
  id bigint generated always as identity primary key,
  sender_id uuid not null default auth.uid(),
  nickname text not null,
  content text not null,
  created_at timestamptz not null default now()
);
alter table chat_group_messages enable row level security;
drop policy if exists "cg read" on chat_group_messages;
create policy "cg read" on chat_group_messages for select to authenticated using (true);
drop policy if exists "cg insert" on chat_group_messages;
create policy "cg insert" on chat_group_messages for insert to authenticated with check (sender_id = auth.uid());

-- ---------- 5. 社区聊天室：私聊 ----------
create table if not exists chat_dm_messages (
  id bigint generated always as identity primary key,
  conv_key text not null,
  sender_id uuid not null default auth.uid(),
  content text not null,
  created_at timestamptz not null default now()
);
alter table chat_dm_messages enable row level security;
drop policy if exists "cd read" on chat_dm_messages;
create policy "cd read" on chat_dm_messages for select to authenticated using (conv_key like '%' || auth.uid() || '%');
drop policy if exists "cd insert" on chat_dm_messages;
create policy "cd insert" on chat_dm_messages for insert to authenticated
  with check (sender_id = auth.uid() and conv_key like '%' || auth.uid() || '%');

-- ============================================================
-- 6. 后台管理函数（口令校验，口令错误抛出 forbidden）
-- ============================================================
create or replace function admin_list_messages(p_secret text)
returns setof guestbook_messages
language plpgsql security definer set search_path = public as $$
begin
  if p_secret is distinct from '_ADMIN_SECRET_' then raise exception 'forbidden'; end if;
  return query select * from guestbook_messages order by id desc;
end $$;

create or replace function admin_set_message_status(p_secret text, p_id bigint, p_status text)
returns void
language plpgsql security definer set search_path = public as $$
begin
  if p_secret is distinct from '_ADMIN_SECRET_' then raise exception 'forbidden'; end if;
  update guestbook_messages set status = p_status where id = p_id;
end $$;

create or replace function admin_delete_message(p_secret text, p_id bigint)
returns void
language plpgsql security definer set search_path = public as $$
begin
  if p_secret is distinct from '_ADMIN_SECRET_' then raise exception 'forbidden'; end if;
  delete from guestbook_messages where id = p_id;
end $$;

-- ---------- 7. 匿名客服聊天函数 ----------
create or replace function chat_send(p_conv_id text, p_name text, p_content text)
returns void
language plpgsql security definer set search_path = public as $$
begin
  if p_conv_id is null or length(p_conv_id) <> 32 or p_conv_id !~ '^[0-9a-f]{32}$'
     or p_content is null or length(p_content) = 0 or length(p_content) > 500 then
    raise exception 'bad request';
  end if;
  insert into chat_messages (conv_id, sender, sender_name, content)
  values (p_conv_id, 'visitor', left(coalesce(p_name, '访客'), 30), p_content);
end $$;

create or replace function chat_send_img(p_conv_id text, p_name text, p_image text, p_content text)
returns void
language plpgsql security definer set search_path = public as $$
begin
  if p_conv_id is null or length(p_conv_id) <> 32 or p_conv_id !~ '^[0-9a-f]{32}$' then
    raise exception 'bad request';
  end if;
  if p_image is null or p_image !~ '^data:image/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$'
     or length(p_image) > 280000 then
    raise exception 'bad image';
  end if;
  insert into chat_messages (conv_id, sender, sender_name, content, image)
  values (p_conv_id, 'visitor', left(coalesce(p_name, '访客'), 30), left(coalesce(p_content, ''), 500), p_image);
end $$;

create or replace function chat_pull(p_conv_id text, p_after_id bigint)
returns setof chat_messages
language plpgsql security definer set search_path = public as $$
begin
  if p_conv_id is null or length(p_conv_id) <> 32 or p_conv_id !~ '^[0-9a-f]{32}$' then
    return;
  end if;
  return query
    select * from chat_messages
    where conv_id = p_conv_id and id > coalesce(p_after_id, 0)
    order by id asc limit 100;
end $$;

create or replace function admin_chat_convs(p_secret text)
returns table (conv_id text, visitor_name text, last_sender text, last_time timestamptz, last_content text)
language plpgsql security definer set search_path = public as $$
begin
  if p_secret is distinct from '_ADMIN_SECRET_' then raise exception 'forbidden'; end if;
  return query
    select m.conv_id,
      (select c2.sender_name from chat_messages c2
        where c2.conv_id = m.conv_id and c2.sender = 'visitor'
        order by c2.id desc limit 1) as visitor_name,
      m.sender as last_sender,
      m.created_at as last_time,
      coalesce(m.content, case when m.image is not null then '[图片]' end) as last_content
    from chat_messages m
    join (select conv_id, max(id) as max_id from chat_messages group by conv_id) t
      on t.conv_id = m.conv_id and t.max_id = m.id
    order by m.id desc;
end $$;

create or replace function admin_chat_pull(p_secret text, p_conv_id text, p_after_id bigint)
returns setof chat_messages
language plpgsql security definer set search_path = public as $$
begin
  if p_secret is distinct from '_ADMIN_SECRET_' then raise exception 'forbidden'; end if;
  return query
    select * from chat_messages
    where conv_id = p_conv_id and id > coalesce(p_after_id, 0)
    order by id asc limit 100;
end $$;

create or replace function admin_chat_reply(p_secret text, p_conv_id text, p_content text)
returns void
language plpgsql security definer set search_path = public as $$
begin
  if p_secret is distinct from '_ADMIN_SECRET_' then raise exception 'forbidden'; end if;
  if p_content is null or length(p_content) = 0 or length(p_content) > 500 then
    raise exception 'bad request';
  end if;
  insert into chat_messages (conv_id, sender, sender_name, content)
  values (p_conv_id, 'admin', '站长', p_content);
end $$;

-- ---------- 8. 聊天室心跳 ----------
create or replace function chat_heartbeat()
returns void
language sql security definer set search_path = public as $$
  update chat_profiles set last_seen = now() where id = auth.uid();
$$;
