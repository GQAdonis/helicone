CREATE SCHEMA IF NOT EXISTS vault;
CREATE EXTENSION IF NOT EXISTS "supabase_vault" WITH SCHEMA "vault" CASCADE;
CREATE EXTENSION IF NOT EXISTS pgsodium;

-- Grant specific function permissions instead of all functions
GRANT USAGE ON SCHEMA pgsodium TO postgres;
GRANT EXECUTE ON FUNCTION pgsodium.create_key() TO postgres;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_aead_det_noncegen() TO postgres;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_aead_det_encrypt() TO postgres;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_aead_det_decrypt() TO postgres;

-- Add columns for encrypted storage
ALTER TABLE provider_keys
ADD COLUMN provider_key TEXT NOT NULL,
    ADD COLUMN key_id uuid NOT NULL DEFAULT (pgsodium.create_key()).id REFERENCES pgsodium.key(id),
    ADD COLUMN nonce bytea NOT NULL DEFAULT pgsodium.crypto_aead_det_noncegen();

ALTER TABLE provider_keys
ALTER COLUMN vault_key_id DROP NOT NULL;

-- Set up encryption for provider_key column
SECURITY LABEL FOR pgsodium ON COLUMN public.provider_keys.provider_key IS 'ENCRYPT WITH KEY COLUMN key_id NONCE nonce ASSOCIATED (org_id)';

-- Create view for decryption access
CREATE OR REPLACE VIEW public.decrypted_provider_keys AS
SELECT 
    id,
    org_id,
    provider_name,
    provider_key_name,
    pgsodium.crypto_aead_det_decrypt(
        provider_key::bytea,
        key_id::uuid,
        nonce,
        org_id::text::bytea
    )::text AS decrypted_provider_key,
    created_at,
    soft_delete,
    vault_key_id,
    key_id,
    nonce,
    provider_key,
    config
FROM provider_keys;