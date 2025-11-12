CREATE TABLE IF NOT EXISTS unhealthy_nodes (
    node_name TEXT NOT NULL PRIMARY KEY,
    marked_unhealthy_at INTEGER NOT NULL DEFAULT 0,
    failure_reason TEXT NOT NULL DEFAULT ''
);
