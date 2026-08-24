-- Persist the exact lease lifetime admitted by Kernel so every renewal and
-- local runner deadline remain bound to the original grant.

ALTER TABLE active_leases
ADD COLUMN ttl_seconds INTEGER NOT NULL DEFAULT 15
CHECK (ttl_seconds BETWEEN 1 AND 15);
