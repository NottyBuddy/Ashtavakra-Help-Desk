CREATE TABLE IF NOT EXISTS call_audits (
  id TEXT PRIMARY KEY,
  agent_name TEXT NOT NULL,
  call_date TEXT,
  auditor_user_id TEXT NOT NULL,
  transcript_sha256 TEXT NOT NULL,
  recording_key TEXT,
  report_json TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending_review',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_call_audits_created_at ON call_audits(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_call_audits_agent ON call_audits(agent_name, created_at DESC);
