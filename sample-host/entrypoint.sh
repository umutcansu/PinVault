#!/bin/sh
# Sunucu root olarak çalışmaz. data/ çoğunlukla docker compose'u çalıştıran
# kullanıcının oluşturduğu bir bağlamadır (bind mount); açılışta sahipliği
# servis kullanıcısına verilir, sonra yetkiler bırakılıp sunucu başlatılır.
# `docker compose exec` ile çalıştırılan araçlar (keytool, softhsm2-util)
# root kalır; oluşturdukları dosyalar bir sonraki açılışta yine düzelir.
set -eu

if [ "$(id -u)" = "0" ]; then
    chown -R pinvault:pinvault /data
    exec setpriv --reuid=pinvault --regid=pinvault --init-groups "$@"
fi
exec "$@"
