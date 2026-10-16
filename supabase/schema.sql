-- =====================================================================
-- Bandeja · schéma Supabase
-- À coller tel quel dans Supabase > SQL Editor > New query, puis Run.
-- Le script peut être relancé sans risque (idempotent).
-- =====================================================================

create extension if not exists pgcrypto;

-- ---------- Tables ----------

create table if not exists public.profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  full_name   text not null default '',
  phone       text,
  is_admin    boolean not null default false,
  created_at  timestamptz not null default now()
);

create table if not exists public.settings (
  id          int primary key default 1 check (id = 1),
  prices      jsonb not null default '{"creuse60":200,"creuse90":300,"pleine60":280,"pleine90":400}',
  updated_at  timestamptz not null default now()
);
insert into public.settings (id) values (1) on conflict (id) do nothing;

create table if not exists public.bookings (
  id               uuid primary key default gen_random_uuid(),
  code             text not null unique,
  user_id          uuid not null references auth.users(id) on delete cascade,
  court_id         text not null check (court_id in ('T1','T2','T3','T4','T5')),
  date             date not null,
  start_min        int  not null,
  duration         int  not null check (duration in (60, 90)),
  players          int  not null check (players in (2, 4)),
  contact_name     text not null,
  phone            text,
  tariff           text not null check (tariff in ('creuse','pleine')),
  price_total      int  not null,
  price_per_player int  not null,
  payment          text not null check (payment in ('sur_place','paye_demo')),
  paid             boolean not null default false,
  status           text not null default 'confirmed' check (status in ('confirmed','cancelled')),
  created_at       timestamptz not null default now(),
  cancelled_at     timestamptz
);
create index if not exists bookings_user_idx on public.bookings(user_id);
create index if not exists bookings_date_idx on public.bookings(date);

create table if not exists public.blocks (
  id          uuid primary key default gen_random_uuid(),
  court_id    text not null check (court_id in ('T1','T2','T3','T4','T5')),
  date        date not null,
  start_min   int  not null,
  end_min     int  not null,
  reason      text,
  created_by  uuid references auth.users(id) on delete set null,
  created_at  timestamptz not null default now()
);

-- Une ligne par tranche de 30 min occupée. La clé primaire rend
-- physiquement impossible deux occupations du même terrain au même moment.
create table if not exists public.slots (
  court_id    text not null,
  date        date not null,
  time_min    int  not null,
  booking_id  uuid references public.bookings(id) on delete cascade,
  block_id    uuid references public.blocks(id)   on delete cascade,
  primary key (court_id, date, time_min),
  check ((booking_id is null) <> (block_id is null))
);
create index if not exists slots_date_idx on public.slots(date);

-- ---------- Profil créé automatiquement à l'inscription ----------

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, full_name, phone)
  values (new.id,
          coalesce(left(btrim(new.raw_user_meta_data->>'full_name'), 60), ''),
          nullif(left(btrim(coalesce(new.raw_user_meta_data->>'phone', '')), 20), ''))
  on conflict (id) do nothing;
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path = public as $$
  select coalesce((select is_admin from public.profiles where id = auth.uid()), false)
$$;

-- ---------- Sécurité (Row Level Security) ----------

alter table public.profiles enable row level security;
alter table public.settings enable row level security;
alter table public.bookings enable row level security;
alter table public.blocks   enable row level security;
alter table public.slots    enable row level security;

drop policy if exists "profil: soi ou gérant"        on public.profiles;
drop policy if exists "tarifs: lecture publique"     on public.settings;
drop policy if exists "résas: joueur ou gérant"      on public.bookings;
drop policy if exists "blocages: lecture publique"   on public.blocks;
drop policy if exists "créneaux: lecture publique"   on public.slots;

create policy "profil: soi ou gérant"      on public.profiles for select using (id = auth.uid() or public.is_admin());
create policy "tarifs: lecture publique"   on public.settings for select using (true);
create policy "résas: joueur ou gérant"    on public.bookings for select using (user_id = auth.uid() or public.is_admin());
create policy "blocages: lecture publique" on public.blocks   for select using (true);
create policy "créneaux: lecture publique" on public.slots    for select using (true);
-- Aucune politique d'écriture : toutes les écritures passent par les fonctions ci-dessous.

-- ---------- Fonctions métier ----------

-- Réserver : contrôle des règles, prix calculé côté serveur, verrous de créneaux.
create or replace function public.create_booking(
  p_court text, p_date date, p_start int, p_duration int,
  p_players int, p_contact text, p_phone text, p_payment text)
returns public.bookings language plpgsql security definer set search_path = public as $$
declare
  v_uid    uuid := auth.uid();
  v_now    timestamp := now() at time zone 'Africa/Casablanca';
  v_start  timestamp := p_date + make_interval(mins => p_start);
  v_alpha  text := 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  v_tariff text;
  v_prices jsonb;
  v_total  int;
  v_code   text;
  v_b      public.bookings;
  v_m      int;
begin
  if v_uid is null then raise exception 'auth'; end if;
  if p_court not in ('T1','T2','T3','T4','T5') or p_duration not in (60, 90) or p_players not in (2, 4)
     or p_start % 30 <> 0 or p_start < 480 or p_start + p_duration > 1440
     or p_payment not in ('sur_place','paye_demo') or coalesce(btrim(p_contact), '') = '' then
    raise exception 'invalid';
  end if;
  if v_start <= v_now or p_date > v_now::date + 7 then raise exception 'past'; end if;

  -- Un joueur à la fois pour la limite de 3 réservations à venir.
  perform pg_advisory_xact_lock(hashtext(v_uid::text));
  if (select count(*) from public.bookings
      where user_id = v_uid and status = 'confirmed'
        and date + make_interval(mins => start_min) > v_now) >= 3 then
    raise exception 'limit';
  end if;

  v_tariff := case when extract(isodow from p_date) in (6, 7) or p_start >= 1020 then 'pleine' else 'creuse' end;
  select prices into v_prices from public.settings where id = 1;
  v_total := coalesce((v_prices ->> (v_tariff || p_duration))::int, 0);

  loop
    v_code := 'BDJ-';
    for i in 1..4 loop
      v_code := v_code || substr(v_alpha, 1 + floor(random() * length(v_alpha))::int, 1);
    end loop;
    exit when not exists (select 1 from public.bookings where code = v_code);
  end loop;

  insert into public.bookings (code, user_id, court_id, date, start_min, duration, players, contact_name,
                               phone, tariff, price_total, price_per_player, payment, paid)
  values (v_code, v_uid, p_court, p_date, p_start, p_duration, p_players, left(btrim(p_contact), 40),
          nullif(left(btrim(coalesce(p_phone, '')), 20), ''), v_tariff, v_total,
          ceil(v_total::numeric / p_players)::int, p_payment, p_payment = 'paye_demo')
  returning * into v_b;

  begin
    for v_m in p_start .. p_start + p_duration - 30 by 30 loop
      insert into public.slots (court_id, date, time_min, booking_id) values (p_court, p_date, v_m, v_b.id);
    end loop;
  exception when unique_violation then
    raise exception 'conflict';
  end;
  return v_b;
end $$;

-- Annuler : le joueur jusqu'à 24 h avant, le gérant à tout moment.
create or replace function public.cancel_booking(p_id uuid)
returns void language plpgsql security definer set search_path = public as $$
declare
  v_b   public.bookings;
  v_now timestamp := now() at time zone 'Africa/Casablanca';
begin
  select * into v_b from public.bookings where id = p_id for update;
  if not found then raise exception 'invalid'; end if;
  if not public.is_admin() then
    if v_b.user_id is distinct from auth.uid() then raise exception 'forbidden'; end if;
    if v_b.date + make_interval(mins => v_b.start_min) - v_now <= interval '24 hours' then
      raise exception 'late';
    end if;
  end if;
  if v_b.status <> 'confirmed' then return; end if;
  update public.bookings set status = 'cancelled', cancelled_at = now() where id = p_id;
  delete from public.slots where booking_id = p_id;
end $$;

create or replace function public.set_paid(p_id uuid, p_paid boolean)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'forbidden'; end if;
  update public.bookings set paid = p_paid where id = p_id;
end $$;

create or replace function public.create_block(p_court text, p_date date, p_start int, p_end int, p_reason text)
returns public.blocks language plpgsql security definer set search_path = public as $$
declare
  v_blk public.blocks;
  v_m   int;
begin
  if not public.is_admin() then raise exception 'forbidden'; end if;
  if p_court not in ('T1','T2','T3','T4','T5') or p_start % 30 <> 0 or p_end % 30 <> 0
     or p_start < 480 or p_end > 1440 or p_end <= p_start then
    raise exception 'invalid';
  end if;
  insert into public.blocks (court_id, date, start_min, end_min, reason, created_by)
  values (p_court, p_date, p_start, p_end, nullif(left(btrim(coalesce(p_reason, '')), 60), ''), auth.uid())
  returning * into v_blk;
  begin
    for v_m in p_start .. p_end - 30 by 30 loop
      insert into public.slots (court_id, date, time_min, block_id) values (p_court, p_date, v_m, v_blk.id);
    end loop;
  exception when unique_violation then
    raise exception 'conflict';
  end;
  return v_blk;
end $$;

create or replace function public.remove_block(p_id uuid)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'forbidden'; end if;
  delete from public.blocks where id = p_id;
end $$;

create or replace function public.save_prices(p_prices jsonb)
returns void language plpgsql security definer set search_path = public as $$
declare k text;
begin
  if not public.is_admin() then raise exception 'forbidden'; end if;
  foreach k in array array['creuse60','creuse90','pleine60','pleine90'] loop
    if (p_prices ->> k) is null or (p_prices ->> k)::int not between 1 and 5000 then
      raise exception 'invalid';
    end if;
  end loop;
  update public.settings
     set prices = jsonb_build_object('creuse60', (p_prices->>'creuse60')::int, 'creuse90', (p_prices->>'creuse90')::int,
                                     'pleine60', (p_prices->>'pleine60')::int, 'pleine90', (p_prices->>'pleine90')::int),
         updated_at = now()
   where id = 1;
end $$;

create or replace function public.update_my_profile(p_name text, p_phone text)
returns void language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'auth'; end if;
  if coalesce(btrim(p_name), '') = '' then raise exception 'invalid'; end if;
  update public.profiles
     set full_name = left(btrim(p_name), 60), phone = nullif(left(btrim(coalesce(p_phone, '')), 20), '')
   where id = auth.uid();
end $$;

-- Seuls les utilisateurs connectés peuvent appeler les fonctions d'écriture.
revoke execute on function public.create_booking(text, date, int, int, int, text, text, text) from public, anon;
revoke execute on function public.cancel_booking(uuid)                    from public, anon;
revoke execute on function public.set_paid(uuid, boolean)                 from public, anon;
revoke execute on function public.create_block(text, date, int, int, text) from public, anon;
revoke execute on function public.remove_block(uuid)                      from public, anon;
revoke execute on function public.save_prices(jsonb)                      from public, anon;
revoke execute on function public.update_my_profile(text, text)           from public, anon;
grant  execute on function public.create_booking(text, date, int, int, int, text, text, text) to authenticated;
grant  execute on function public.cancel_booking(uuid)                    to authenticated;
grant  execute on function public.set_paid(uuid, boolean)                 to authenticated;
grant  execute on function public.create_block(text, date, int, int, text) to authenticated;
grant  execute on function public.remove_block(uuid)                      to authenticated;
grant  execute on function public.save_prices(jsonb)                      to authenticated;
grant  execute on function public.update_my_profile(text, text)           to authenticated;

-- ---------- Temps réel ----------

do $$
begin
  begin alter publication supabase_realtime add table public.slots;    exception when duplicate_object then null; end;
  begin alter publication supabase_realtime add table public.settings; exception when duplicate_object then null; end;
  begin alter publication supabase_realtime add table public.bookings; exception when duplicate_object then null; end;
end $$;

-- ---------- Désigner le gérant du club ----------
-- Après vous être inscrit dans l'app, remplacez l'adresse ci-dessous et exécutez cette ligne seule :
-- update public.profiles set is_admin = true where id = (select id from auth.users where email = 'votre.email@exemple.com');
