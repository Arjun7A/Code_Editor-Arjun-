-- Verification query for Security Gate core tables on Supabase
-- Run in Supabase SQL Editor after 001_create_core_tables.sql

select table_name, count(*) as column_count
from information_schema.columns
where table_schema = 'public'
  and table_name in ('pull_requests', 'scan_results', 'audit_logs')
group by table_name
order by table_name;

select
    p.id as pull_request_id,
    p.repo_name,
    p.pr_number,
    p.status,
    p.risk_score,
    p.verdict,
    count(s.id) as scan_rows,
    a.id as audit_log_id
from public.pull_requests p
left join public.scan_results s on s.pr_id = p.id
left join public.audit_logs a on a.pr_id = p.id
group by p.id, a.id
order by p.created_at desc
limit 20;
