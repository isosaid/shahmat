-- =====================================================================
--  SHAHMATNAMEH — схема базы данных (PostgreSQL / Supabase)
--  Выполните этот файл целиком в Supabase → SQL Editor → New query → Run
-- =====================================================================

-- ---------------------------------------------------------------
-- 1. ПРОФИЛИ
--    auth.users создаётся Supabase автоматически и хранит почту и
--    надёжно захешированный пароль. Здесь — только доп. данные.
-- ---------------------------------------------------------------
create table if not exists public.profiles (
  id           uuid primary key references auth.users(id) on delete cascade,
  email        text,
  first_name   text,
  last_name    text,
  phone        text,
  country      text,
  city         text,
  about        text,
  level        text default 'beginner',
  role         text not null default 'user'
               check (role in ('user','coach','admin')),
  blocked      boolean not null default false,
  -- шахматные данные (ТЗ п. 6.2)
  fide_id      text,
  rating       integer,
  chess_rank   text,
  club         text,
  coach_name   text,
  time_control text,
  -- служебное
  points       integer not null default 0,
  created_at   timestamptz not null default now(),
  last_active  timestamptz
);

-- ---------------------------------------------------------------
-- 2. ПРОГРЕСС ОБУЧЕНИЯ
-- ---------------------------------------------------------------
create table if not exists public.lesson_progress (
  id          bigserial primary key,
  user_id     uuid not null references auth.users(id) on delete cascade,
  lesson_id   text not null,
  course_id   text,
  completed   boolean not null default true,
  completed_at timestamptz not null default now(),
  unique (user_id, lesson_id)
);

create table if not exists public.quiz_results (
  id          bigserial primary key,
  user_id     uuid not null references auth.users(id) on delete cascade,
  lesson_id   text not null,
  score_pct   integer not null,
  passed      boolean not null default false,
  attempts    integer not null default 1,
  created_at  timestamptz not null default now(),
  unique (user_id, lesson_id)
);

create table if not exists public.puzzle_results (
  id          bigserial primary key,
  user_id     uuid not null references auth.users(id) on delete cascade,
  puzzle_id   text not null,
  solved      boolean not null default true,
  attempts    integer not null default 1,
  created_at  timestamptz not null default now(),
  unique (user_id, puzzle_id)
);

-- ---------------------------------------------------------------
-- 3. СЕРТИФИКАТЫ
-- ---------------------------------------------------------------
create table if not exists public.certificates (
  id          bigserial primary key,
  user_id     uuid not null references auth.users(id) on delete cascade,
  course_id   text not null,
  serial      text not null unique,
  score_pct   integer,
  issued_at   timestamptz not null default now()
);

-- ---------------------------------------------------------------
-- 4. ИСТОРИЯ АКТИВНОСТИ
-- ---------------------------------------------------------------
create table if not exists public.activity_log (
  id          bigserial primary key,
  user_id     uuid not null references auth.users(id) on delete cascade,
  kind        text not null,
  text        text,
  created_at  timestamptz not null default now()
);

-- ---------------------------------------------------------------
-- 5. КОНТЕНТ, УПРАВЛЯЕМЫЙ АДМИНИСТРАТОРОМ
-- ---------------------------------------------------------------
create table if not exists public.news (
  id          bigserial primary key,
  category    text,
  title_ru    text, title_tj text, title_en text,
  body_ru     text, body_tj text, body_en text,
  author      text,
  views       integer not null default 0,
  published   boolean not null default true,
  created_at  timestamptz not null default now()
);

create table if not exists public.courses (
  id          text primary key,
  level       text,
  title_ru    text, title_tj text, title_en text,
  desc_ru     text, desc_tj text, desc_en text,
  author      text,
  minutes     integer,
  status      text default 'published',
  sort_order  integer default 0
);

-- ---------------------------------------------------------------
-- 6. ВСПОМОГАТЕЛЬНАЯ ФУНКЦИЯ: проверка администратора
--    security definer нужен, чтобы политика не зациклилась на самой себе
-- ---------------------------------------------------------------
create or replace function public.is_admin()
returns boolean
language sql stable security definer set search_path = public
as $$
  select exists (select 1 from public.profiles
                 where id = auth.uid() and role = 'admin');
$$;

-- ---------------------------------------------------------------
-- 7. ПОЛИТИКИ ДОСТУПА (Row Level Security)
--    Это и есть настоящая защита: она работает на сервере,
--    подделать её из браузера невозможно.
-- ---------------------------------------------------------------
alter table public.profiles        enable row level security;
alter table public.lesson_progress enable row level security;
alter table public.quiz_results    enable row level security;
alter table public.puzzle_results  enable row level security;
alter table public.certificates    enable row level security;
alter table public.activity_log    enable row level security;
alter table public.news            enable row level security;
alter table public.courses         enable row level security;

-- профиль: свой — читать и менять; админ — видеть и менять все
drop policy if exists p_self_read on public.profiles;
create policy p_self_read   on public.profiles for select
  using (id = auth.uid() or public.is_admin());
drop policy if exists p_self_write on public.profiles;
create policy p_self_write  on public.profiles for update
  using (id = auth.uid() or public.is_admin());
drop policy if exists p_self_insert on public.profiles;
create policy p_self_insert on public.profiles for insert
  with check (id = auth.uid());
drop policy if exists p_admin_del on public.profiles;
create policy p_admin_del   on public.profiles for delete
  using (public.is_admin());

-- прогресс, тесты, задачи, сертификаты, активность: свои — полностью,
-- админ и тренер — только чтение
do $$
declare tbl text;
begin
  foreach tbl in array array['lesson_progress','quiz_results','puzzle_results','certificates','activity_log']
  loop
    execute format('drop policy if exists p_own_all on public.%I', tbl);
    execute format(
      'create policy p_own_all on public.%I for all
         using (user_id = auth.uid()) with check (user_id = auth.uid())', tbl);
    execute format('drop policy if exists p_staff_read on public.%I', tbl);
    execute format(
      'create policy p_staff_read on public.%I for select
         using (public.is_admin()
                or exists (select 1 from public.profiles
                           where id = auth.uid() and role in (''admin'',''coach'')))', tbl);
  end loop;
end $$;

-- новости и курсы: читают все, изменяет только админ
drop policy if exists p_news_read on public.news;
create policy p_news_read  on public.news    for select using (published or public.is_admin());
drop policy if exists p_news_write on public.news;
create policy p_news_write on public.news    for all    using (public.is_admin()) with check (public.is_admin());
drop policy if exists p_crs_read on public.courses;
create policy p_crs_read   on public.courses for select using (true);
drop policy if exists p_crs_write on public.courses;
create policy p_crs_write  on public.courses for all    using (public.is_admin()) with check (public.is_admin());

-- ---------------------------------------------------------------
-- 8. АВТОСОЗДАНИЕ ПРОФИЛЯ ПРИ РЕГИСТРАЦИИ
-- ---------------------------------------------------------------
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public
as $$
begin
  insert into public.profiles (id, email, first_name, last_name, phone, level)
  values (new.id, new.email,
          new.raw_user_meta_data->>'first_name',
          new.raw_user_meta_data->>'last_name',
          new.raw_user_meta_data->>'phone',
          coalesce(new.raw_user_meta_data->>'level','beginner'))
  on conflict (id) do nothing;
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ---------------------------------------------------------------
-- 9. ПРЕДСТАВЛЕНИЕ ДЛЯ ДАШБОРДА АДМИНИСТРАТОРА
-- ---------------------------------------------------------------
create or replace view public.admin_dashboard as
select
  p.id, p.email, p.first_name, p.last_name, p.country, p.city,
  p.level, p.role, p.blocked, p.rating, p.points,
  p.created_at, p.last_active,
  (select count(*) from public.lesson_progress lp where lp.user_id = p.id) as lessons_done,
  (select count(*) from public.puzzle_results pr where pr.user_id = p.id and pr.solved) as puzzles_done,
  (select count(*) from public.certificates c  where c.user_id  = p.id) as certificates,
  (select round(avg(q.score_pct)) from public.quiz_results q where q.user_id = p.id) as avg_quiz
from public.profiles p;

-- ---------------------------------------------------------------
-- 10. НАЗНАЧЕНИЕ АДМИНИСТРАТОРА
--     Сначала зарегистрируйтесь на сайте обычным способом,
--     затем подставьте свою почту и выполните эту строку.
-- ---------------------------------------------------------------
-- update public.profiles set role = 'admin' where email = 'ваша@почта';

-- =====================================================================
--  ЧАСТЬ 2: ЧАТ
--  Добавляется к уже существующей схеме. Выполните этот блок,
--  если база уже создана и нужно добавить только чат.
-- =====================================================================

-- ---------------------------------------------------------------
-- 11. КОМНАТЫ ЧАТА
--     general — общий чат платформы, доступен всем вошедшим.
--     Можно создавать тематические комнаты и личную переписку.
-- ---------------------------------------------------------------
create table if not exists public.chat_rooms (
  id          text primary key,
  title       text not null,
  kind        text not null default 'public'
              check (kind in ('public','course','direct')),
  course_id   text,
  created_at  timestamptz not null default now()
);

insert into public.chat_rooms (id, title, kind) values
  ('general', 'Общий чат', 'public'),
  ('help',    'Вопросы по обучению', 'public')
on conflict (id) do nothing;

-- ---------------------------------------------------------------
-- 12. СООБЩЕНИЯ
-- ---------------------------------------------------------------
create table if not exists public.chat_messages (
  id          bigserial primary key,
  room_id     text not null references public.chat_rooms(id) on delete cascade,
  user_id     uuid not null references auth.users(id) on delete cascade,
  author_name text,
  body        text not null check (char_length(body) between 1 and 2000),
  deleted     boolean not null default false,
  created_at  timestamptz not null default now()
);

create index if not exists idx_chat_room_time
  on public.chat_messages (room_id, created_at desc);

-- ---------------------------------------------------------------
-- 13. ПОЛИТИКИ ДОСТУПА ДЛЯ ЧАТА
--     Читают все вошедшие; писать можно только от своего имени;
--     удалять — автор своё, администратор любое.
--     Заблокированные писать не могут — это проверяется на сервере.
-- ---------------------------------------------------------------
alter table public.chat_rooms    enable row level security;
alter table public.chat_messages enable row level security;

drop policy if exists c_rooms_read on public.chat_rooms;
create policy c_rooms_read on public.chat_rooms for select
  using (auth.uid() is not null);

drop policy if exists c_rooms_admin on public.chat_rooms;
create policy c_rooms_admin on public.chat_rooms for all
  using (public.is_admin()) with check (public.is_admin());

drop policy if exists c_msg_read on public.chat_messages;
create policy c_msg_read on public.chat_messages for select
  using (auth.uid() is not null);

drop policy if exists c_msg_write on public.chat_messages;
create policy c_msg_write on public.chat_messages for insert
  with check (
    user_id = auth.uid()
    and not exists (select 1 from public.profiles
                    where id = auth.uid() and blocked = true)
  );

drop policy if exists c_msg_edit on public.chat_messages;
create policy c_msg_edit on public.chat_messages for update
  using (user_id = auth.uid() or public.is_admin());

drop policy if exists c_msg_del on public.chat_messages;
create policy c_msg_del on public.chat_messages for delete
  using (user_id = auth.uid() or public.is_admin());

-- ---------------------------------------------------------------
-- 14. МГНОВЕННАЯ ДОСТАВКА СООБЩЕНИЙ
--     Включает Realtime: новые сообщения приходят сразу,
--     без перезагрузки страницы.
-- ---------------------------------------------------------------
do $$
begin
  if not exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime' and tablename = 'chat_messages'
  ) then
    alter publication supabase_realtime add table public.chat_messages;
  end if;
exception when others then
  raise notice 'Realtime не настроен — чат будет обновляться опросом каждые 5 секунд';
end $$;

-- =====================================================================
--  ЧАСТЬ 3: ОНЛАЙН-ПАРТИИ
--  Позволяет двум игрокам играть с разных устройств.
--  Без этой таблицы онлайн-режим работать не может: ходы просто
--  негде передавать между браузерами.
-- =====================================================================

create table if not exists public.chess_games (
  room_id     text primary key,
  fen         text not null,
  moves_san   text default '',   -- ходы партии в шахматной нотации
  last_from   text,
  last_to     text,
  white_id    uuid references auth.users(id) on delete set null,
  black_id    uuid references auth.users(id) on delete set null,
  white_name  text,
  black_name  text,
  move_no     integer not null default 0,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

create index if not exists idx_chess_games_updated
  on public.chess_games (updated_at desc);

alter table public.chess_games enable row level security;

-- Играть может любой вошедший: комната защищена кодом,
-- который знают только два игрока.
drop policy if exists g_read on public.chess_games;
create policy g_read  on public.chess_games for select
  using (auth.uid() is not null);

drop policy if exists g_write on public.chess_games;
create policy g_write on public.chess_games for insert
  with check (auth.uid() is not null);

drop policy if exists g_update on public.chess_games;
create policy g_update on public.chess_games for update
  using (auth.uid() is not null);

drop policy if exists g_del on public.chess_games;
create policy g_del on public.chess_games for delete
  using (white_id = auth.uid() or black_id = auth.uid() or public.is_admin());

-- мгновенная передача ходов, если включён Realtime
do $$
begin
  if not exists (
    select 1 from pg_publication_tables
    where pubname='supabase_realtime' and tablename='chess_games'
  ) then
    alter publication supabase_realtime add table public.chess_games;
  end if;
exception when others then
  raise notice 'Realtime не настроен — ходы будут приходить опросом раз в 2 секунды';
end $$;
