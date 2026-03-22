create table if not exists public.scan_history (
  id bigint generated always as identity primary key,
  repo_url text not null,
  pr_url text not null,
  scanned_at timestamptz not null default timezone('utc', now()),
  scan_summary jsonb not null,
  issues jsonb not null default '[]'::jsonb,
  ai_audit jsonb not null default '{}'::jsonb,
  gitleaks jsonb not null default '[]'::jsonb,
  checkov jsonb not null default '[]'::jsonb
);

create index if not exists scan_history_scanned_at_idx
  on public.scan_history (scanned_at desc);

alter table public.scan_history enable row level security;
