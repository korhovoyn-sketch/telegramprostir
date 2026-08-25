-- Відбиток схеми: функції (з хешем визначення), політики, колонки,
-- обмеження й ACL. Використовується, щоб довести, що склеєний RELEASE.sql
-- дає ТУ САМУ схему, що поштучний накат міграцій.
SELECT 'FN '||p.proname||'('||pg_get_function_identity_arguments(p.oid)||') :: '
       || md5(pg_get_functiondef(p.oid))
FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace AND n.nspname='public'
ORDER BY 1;
SELECT 'POL '||schemaname||'.'||tablename||'.'||policyname||' :: '||cmd||' :: '||roles::text
       ||' :: '||md5(COALESCE(qual,'')||'|'||COALESCE(with_check,''))
FROM pg_policies WHERE schemaname IN ('public','storage') ORDER BY 1;
SELECT 'COL '||table_name||'.'||column_name||' :: '||data_type||' :: '||is_nullable
       ||' :: '||COALESCE(column_default,'-')
FROM information_schema.columns WHERE table_schema='public' ORDER BY 1;
SELECT 'CON '||conrelid::regclass::text||'.'||conname||' :: '||pg_get_constraintdef(oid)
FROM pg_constraint WHERE connamespace='public'::regnamespace ORDER BY 1;
SELECT 'ACL '||p.proname||' :: anon='||has_function_privilege('anon',p.oid,'EXECUTE')::text
       ||' auth='||has_function_privilege('authenticated',p.oid,'EXECUTE')::text
FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace AND n.nspname='public' ORDER BY 1;
