-- Cihazın dosyayı hangi yetkilendirme ile aldığını takip et: public / token /
-- token_mtls / api_key. Web UI "Dağıtım Geçmişi" kartında + mobile log'larda
-- görünür olacak.
ALTER TABLE vault_distributions ADD COLUMN auth_method TEXT;
