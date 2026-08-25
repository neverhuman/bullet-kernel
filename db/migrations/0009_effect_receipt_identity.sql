-- Incompatible effect-receipt identity boundary. Schema-8 databases may
-- contain legacy rcp_ subjects and are refused rather than upgraded.

CREATE TABLE effect_receipt_identity_contract (
  singleton       INTEGER PRIMARY KEY CHECK (singleton = 1),
  identity_format TEXT NOT NULL CHECK (
    identity_format = 'bullet-wire-v1alpha1-effect-receipt-efr-blake3-256-lower'
  )
);

INSERT INTO effect_receipt_identity_contract (singleton, identity_format)
VALUES (1, 'bullet-wire-v1alpha1-effect-receipt-efr-blake3-256-lower');

CREATE TRIGGER effect_receipt_id_insert_v1
BEFORE INSERT ON effect_receipts
WHEN typeof(NEW.id) != 'text'
  OR length(NEW.id) != 68
  OR substr(NEW.id, 1, 4) != 'efr_'
  OR substr(NEW.id, 5) GLOB '*[^0-9a-f]*'
BEGIN
  SELECT RAISE(ABORT, 'INVALID_EFFECT_RECEIPT_ID');
END;

CREATE TRIGGER effect_receipt_id_update_v1
BEFORE UPDATE OF id ON effect_receipts
WHEN typeof(NEW.id) != 'text'
  OR length(NEW.id) != 68
  OR substr(NEW.id, 1, 4) != 'efr_'
  OR substr(NEW.id, 5) GLOB '*[^0-9a-f]*'
BEGIN
  SELECT RAISE(ABORT, 'INVALID_EFFECT_RECEIPT_ID');
END;
