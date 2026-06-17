ALTER TABLE refresh_tokens ADD COLUMN token_hash VARCHAR(255) NOT NULL UNIQUE;
CREATE INDEX idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);
