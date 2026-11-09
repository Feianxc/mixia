#!/bin/sh
# 清空服务器上的密匣数据，恢复到未初始化状态。只在还没有真实数据时使用。
set -eu
hash="$1"
systemctl stop mixia-server
find /var/lib/mixia -mindepth 1 -delete
sed -i "s/^MIXIA_BOOTSTRAP_TOKEN_SHA256=.*/MIXIA_BOOTSTRAP_TOKEN_SHA256=$hash/" /etc/mixia/env
systemctl start mixia-server
sleep 1
curl -s -m 5 http://127.0.0.1:18790/v1/info; echo
