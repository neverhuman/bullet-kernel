-- Budget reservations. Unknown liability is a retained column and is never
-- folded into remaining capacity.

CREATE TABLE budget_reservations (
  reservation_id TEXT PRIMARY KEY CHECK (
    typeof(reservation_id) = 'text'
    AND length(reservation_id) > 0
  ),
  amount INTEGER NOT NULL CHECK (
    typeof(amount) = 'integer'
    AND amount >= 0
  ),
  settled_amount INTEGER CHECK (
    settled_amount IS NULL
    OR (typeof(settled_amount) = 'integer' AND settled_amount >= 0)
  ),
  unknown_liability INTEGER NOT NULL DEFAULT 0 CHECK (
    typeof(unknown_liability) = 'integer'
    AND unknown_liability >= 0
  )
);
