-- Marmot transport payloads are opaque binary data encoded as base64:
--   445   = encrypted MLS group envelope
--   30443 = public MLS KeyPackage bytes
-- Neither is plaintext that NIP-50 can use. Keeping their generated vector
-- NULL also prevents ciphertext tokens from consuming index space or search
-- candidate budgets.
--
-- Preserve the search policy already installed on both fresh and brownfield
-- databases by wrapping, rather than replacing, the current expression. This
-- follows migration 0014's additive pattern and keeps the 0001 checksum frozen.
DO $$
DECLARE
    existing_expression TEXT;
BEGIN
    SELECT pg_get_expr(d.adbin, d.adrelid)
      INTO existing_expression
      FROM pg_attrdef d
      JOIN pg_attribute a
        ON a.attrelid = d.adrelid
       AND a.attnum = d.adnum
     WHERE d.adrelid = 'events'::regclass
       AND a.attname = 'search_tsv';

    IF existing_expression IS NULL THEN
        RAISE EXCEPTION 'events.search_tsv generated expression not found';
    END IF;

    ALTER TABLE events DROP COLUMN search_tsv;
    EXECUTE format(
        'ALTER TABLE events ADD COLUMN search_tsv TSVECTOR GENERATED ALWAYS AS (CASE WHEN kind IN (445, 30443) THEN NULL::tsvector ELSE (%s) END) STORED',
        existing_expression
    );
    CREATE INDEX idx_events_search_tsv ON events USING GIN (search_tsv);
END $$;
