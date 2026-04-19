-- V3: vault_distributions'a başarısızlık nedeni ekle
-- Mobil tarafta fetch başarısız olursa (401/404/decrypt-fail/network) sebep
-- string'i buraya gelir. Web UI dağıtım tablosunda "Neden" kolonunda gösterilir.

ALTER TABLE vault_distributions ADD COLUMN failure_reason TEXT;
