-- Retain actual native invocation metadata. Existing rows deliberately remain
-- NULL and cannot qualify a loaded credential for a new privileged consumer.
ALTER TABLE credential_consumer_verifications ADD COLUMN native_receipt_bytes BLOB
CHECK (native_receipt_bytes IS NULL OR
       (result = 'verified' AND restart_observed = 1 AND
        length(native_receipt_bytes) BETWEEN 2 AND 262144));
