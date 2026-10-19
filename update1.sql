-- জ্ঞানকুঞ্জ: অতিরিক্ত migration
-- পূর্বশর্ত: মূল setup.sql সফলভাবে চালানো এবং public.my_role() function থাকা আবশ্যক।
-- Supabase SQL Editor-এ চালানোর আগে backup নিন এবং staging-এ পরীক্ষা করুন।

-- ১) পণ্যের ছবি আপলোডের জন্য স্টোরেজ bucket
insert into storage.buckets(id, name, public)
values ('product-images', 'product-images', true)
on conflict (id) do nothing;

-- একই নামের policy আগে থাকলে পুনরায় তৈরি করতে সমস্যা এড়ানো
drop policy if exists "staff upload" on storage.objects;
create policy "staff upload" on storage.objects
for insert to authenticated
with check (
  bucket_id = 'product-images'
  and public.my_role() in ('admin', 'stock')
);

drop policy if exists "staff delete" on storage.objects;
create policy "staff delete" on storage.objects
for delete to authenticated
using (
  bucket_id = 'product-images'
  and public.my_role() in ('admin', 'stock')
);

-- ২) অর্ডার সম্পন্ন হলে স্টক কমানো ও বিক্রি রেকর্ড করা—একটি transaction-এর মধ্যে
create or replace function public.set_order_status(p_id uuid, p_status text)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  o public.orders;
  it jsonb;
  pr public.products;
begin
  if coalesce(public.my_role(), '') not in ('admin', 'orders') then
    raise exception 'অনুমতি নেই';
  end if;

  if p_status not in ('অনুরোধ পাঠানো হয়েছে','যাচাই চলছে','নিশ্চিত','প্রস্তুত','ডেলিভারি সম্পন্ন','বাতিল') then
    raise exception 'অবৈধ অর্ডার অবস্থা';
  end if;

  select * into o from public.orders where id = p_id for update;
  if not found then raise exception 'অর্ডার পাওয়া যায়নি'; end if;
  if o.status = 'ডেলিভারি সম্পন্ন' then
    raise exception 'সম্পন্ন অর্ডারের অবস্থা আর বদলানো যায় না';
  end if;

  if p_status = 'ডেলিভারি সম্পন্ন' then
    for it in select * from jsonb_array_elements(o.items) loop
      update public.products
      set qty = qty - (it->>'qty')::int
      where id = it->>'id' and qty >= (it->>'qty')::int
      returning * into pr;

      if not found then
        raise exception 'স্টক যথেষ্ট নেই: %', it->>'name';
      end if;

      insert into public.sales(product_id, name, qty, total, cost_total, payment, customer, by_email)
      values (
        pr.id, pr.name, (it->>'qty')::int,
        (it->>'price')::numeric * (it->>'qty')::int,
        pr.cost * (it->>'qty')::int, 'অনলাইন অর্ডার', o.name, auth.email()
      );
    end loop;
  end if;

  update public.orders set status = p_status where id = p_id;
end;
$$;

revoke all on function public.set_order_status(uuid, text) from public, anon;
grant execute on function public.set_order_status(uuid, text) to authenticated;

-- ৩) স্টাফ যোগ/ভূমিকা পরিবর্তন
create or replace function public.add_staff(p_email text, p_role text)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if coalesce(public.my_role(), '') <> 'admin' then
    raise exception 'অনুমতি নেই';
  end if;
  if p_role not in ('admin','accounts','stock','orders','viewer') then
    raise exception 'ভূমিকা ভুল';
  end if;
  if lower(trim(p_email)) = lower(auth.email()) then
    raise exception 'নিজের ভূমিকা এখানে বদলানো যাবে না';
  end if;

  insert into public.staff(user_id, email, role)
  select id, email, p_role
  from auth.users
  where lower(email) = lower(trim(p_email))
  on conflict (user_id) do update set role = excluded.role;

  if not found then
    raise exception 'এই ইমেইলে কোনো ইউজার নেই। আগে Authentication > Users থেকে বানান';
  end if;
end;
$$;

revoke all on function public.add_staff(text, text) from public, anon;
grant execute on function public.add_staff(text, text) to authenticated;
