-- One row per message check. Stores the result only, never the message text.
create table public.analysis_log (
  id bigint generated always as identity primary key,
  created_at timestamptz not null default now(),
  score integer not null check (score between 0 and 100),
  risk_level text not null check (risk_level in ('high', 'medium', 'low')),
  rules text[] not null default '{}',
  source text not null default 'user' check (source in ('user', 'evaluation')),
  batch text,
  expected_phishing boolean
);

comment on table public.analysis_log is 'Result of each PhishGuard check (score, risk level, rule names). No message text is stored.';
comment on column public.analysis_log.source is 'user = a check made in the app, evaluation = a labelled test set run through the same rules';
comment on column public.analysis_log.batch is 'Name of the evaluation set, null for user checks';
comment on column public.analysis_log.expected_phishing is 'Known label for evaluation rows, null for user checks';

create index analysis_log_created_at_idx on public.analysis_log (created_at);

alter table public.analysis_log enable row level security;

-- The dashboard reads totals and trends with the public key. The rows hold only
-- scores and rule names, so reading them exposes nothing personal.
create policy "Anyone can read analysis results"
  on public.analysis_log for select
  using (true);

-- No insert, update or delete policy: only the Edge Function (service role) can write.
