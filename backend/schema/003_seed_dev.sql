-- ============================================================================
-- DEV ONLY. Do not run against a production register.
-- Seeds one device and one open batch so the integration tests have somewhere
-- to enrol into.
--
-- Replace the placeholders before running:
--   :device_uuid   a uuid4 you generated
--   :device_pubkey the Ed25519 public key hex from scripts/gen_keys.py
-- ============================================================================

INSERT INTO device_registry (device_id, label, public_key)
VALUES ('00000000-0000-4000-8000-000000000001', 'dev-pi-line-1',
        'REPLACE_WITH_DEVICE_ED25519_PUBKEY_HEX')
ON CONFLICT (device_id) DO NOTHING;

INSERT INTO batches (batch_ref, product_name, mfg_date, shelf_life_days, quota,
                     opened_by, countersigned_by)
VALUES ('DEV-TEST-001', 'Dev Test Product 500mg', CURRENT_DATE, 730, 1000,
        'dev-operator-a', 'dev-operator-b')
ON CONFLICT (batch_ref) DO NOTHING;
