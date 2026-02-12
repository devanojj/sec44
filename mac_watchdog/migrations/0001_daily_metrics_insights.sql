CREATE TABLE IF NOT EXISTS daily_metrics(
  date TEXT PRIMARY KEY,
  risk_score INTEGER NOT NULL,
  high_count INTEGER NOT NULL,
  warn_count INTEGER NOT NULL,
  info_count INTEGER NOT NULL,
  failed_logins INTEGER NOT NULL,
  new_listeners INTEGER NOT NULL,
  new_processes INTEGER NOT NULL,
  suspicious_execs INTEGER NOT NULL,
  baseline_deltas_json TEXT NOT NULL,
  drivers_json TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS insights(
  id INTEGER PRIMARY KEY,
  ts TEXT NOT NULL,
  insight_type TEXT NOT NULL,
  source TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence TEXT NOT NULL,
  title TEXT NOT NULL,
  explanation TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  action_text TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  count INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_insights_ts ON insights(ts);
CREATE INDEX IF NOT EXISTS idx_insights_status ON insights(status);
CREATE INDEX IF NOT EXISTS idx_insights_severity ON insights(severity);
CREATE INDEX IF NOT EXISTS idx_insights_fingerprint ON insights(fingerprint);
CREATE INDEX IF NOT EXISTS idx_daily_metrics_date ON daily_metrics(date);
