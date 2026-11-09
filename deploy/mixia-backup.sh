#!/bin/sh
# 备份的全是密文。保留 14 天，存放在只有 root 可读的目录，和运行账号分离。
set -eu
umask 077
dest=/var/backups/mixia
mkdir -p "$dest"
stamp=$(date +%Y%m%dT%H%M%S)
set -a; . /etc/mixia/env; set +a
/srv/apps/mixia/current/mixia-server backup "$dest/mixia-$stamp.db"
# 先数据库后附件：数据库引用的文件都在副本里
tar -C /var/lib/mixia -czf "$dest/mixia-$stamp-blobs.tgz" blobs 2>/dev/null || true
find "$dest" -type f -mtime +14 -delete
