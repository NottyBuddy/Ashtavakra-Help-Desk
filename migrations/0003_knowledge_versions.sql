CREATE TABLE IF NOT EXISTS knowledge_entry_versions (
  id TEXT PRIMARY KEY,
  knowledge_entry_id TEXT NOT NULL REFERENCES knowledge_entries(id) ON DELETE CASCADE,
  version_number INTEGER NOT NULL,
  title TEXT NOT NULL,
  category TEXT NOT NULL,
  content TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending','approved','rejected')),
  changed_by TEXT REFERENCES users(id),
  created_at INTEGER NOT NULL,
  UNIQUE(knowledge_entry_id, version_number)
);
CREATE INDEX IF NOT EXISTS idx_knowledge_versions_entry ON knowledge_entry_versions(knowledge_entry_id, version_number DESC);
INSERT OR IGNORE INTO knowledge_entry_versions(id,knowledge_entry_id,version_number,title,category,content,status,changed_by,created_at)
SELECT lower(hex(randomblob(16))),id,1,title,category,content,status,submitted_by,updated_at
FROM knowledge_entries;
