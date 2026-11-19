CREATE TABLE IF NOT EXISTS ai_feedback (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 question TEXT NOT NULL, answer TEXT NOT NULL, rating INTEGER NOT NULL CHECK(rating IN (-1,1)),
 comment TEXT, status TEXT NOT NULL DEFAULT 'new' CHECK(status IN ('new','reviewed','ignored')),
 created_at INTEGER NOT NULL, reviewed_at INTEGER, reviewed_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_ai_feedback_status_created ON ai_feedback(status,created_at DESC);
CREATE TABLE IF NOT EXISTS knowledge_entries (
 id TEXT PRIMARY KEY, submitted_by TEXT NOT NULL REFERENCES users(id),
 title TEXT NOT NULL, category TEXT NOT NULL, content TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
 reviewed_by TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_knowledge_status_updated ON knowledge_entries(status,updated_at DESC);
