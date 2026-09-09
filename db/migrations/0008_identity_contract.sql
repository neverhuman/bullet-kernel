-- Incompatible V1 identity boundary. Pre-normalization databases stop at
-- migration 7 and are deliberately refused rather than upgraded or mixed.

CREATE TABLE identity_contract (
  singleton       INTEGER PRIMARY KEY CHECK (singleton = 1),
  identity_format TEXT NOT NULL CHECK (
    identity_format = 'bullet-wire-v1alpha1-blake3-256-lower'
  )
);

INSERT INTO identity_contract (singleton, identity_format)
VALUES (1, 'bullet-wire-v1alpha1-blake3-256-lower');
