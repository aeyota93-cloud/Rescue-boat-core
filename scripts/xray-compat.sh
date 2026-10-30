#!/usr/bin/env bash
# Сторож совместимости: пускает ли сервер Xray (Reality) клиента — ядро Шлюпки (sing-box с
# patches/hiddify-sing-box). Так 30.10.2026 узнали поздно: Xray 26.9.8+ перестал пускать sing-box.
#
#   scripts/xray-compat.sh <sing-box> <xray> [<xray> ...]
#
# На каждый xray: одноразовые ключи Reality, сервер и клиент на 127.0.0.1, запрос через туннель.
# Код выхода 1, если хоть один xray не пустил. Нужны curl и openssl; ходит в интернет.
set -euo pipefail

sb=$1
shift
# Reality притворяется этим сайтом: чужие соединения уходят к нему.
target=${XRAY_COMPAT_TARGET:-www.cloudflare.com}
work=$(mktemp -d)
pids=()
cleanup() {
	for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
	rm -rf "$work"
}
trap cleanup EXIT

fail=0
port=24000
summary="| Xray | Шлюпка (chrome) |"$'\n'"|---|---|"
for xray in "$@"; do
	ver=$("$xray" version | head -1 | awk '{print $2}')
	keys=$("$xray" x25519)
	# Старый вывод: «Private key / Public key», новый: «PrivateKey / Password (PublicKey)».
	priv=$(grep -i -m1 'private' <<<"$keys" | awk -F': *' '{print $2}')
	pub=$(grep -i -m1 -E 'public|password' <<<"$keys" | awk -F': *' '{print $2}')
	sid=$(openssl rand -hex 8)
	uid=$(cat /proc/sys/kernel/random/uuid)
	sport=$port
	cport=$((port + 1))
	port=$((port + 2))

	cat >"$work/server-$ver.json" <<EOF
{"log":{"loglevel":"warning"},
 "inbounds":[{"listen":"127.0.0.1","port":$sport,"protocol":"vless",
  "settings":{"clients":[{"id":"$uid","flow":"xtls-rprx-vision"}],"decryption":"none"},
  "streamSettings":{"network":"raw","security":"reality","realitySettings":{
   "target":"$target:443","serverNames":["$target"],"privateKey":"$priv","shortIds":["$sid"]}}}],
 "outbounds":[{"protocol":"freedom"}]}
EOF
	cat >"$work/client-$ver.json" <<EOF
{"log":{"level":"error"},
 "inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":$cport}],
 "outbounds":[{"type":"vless","server":"127.0.0.1","server_port":$sport,"uuid":"$uid",
  "flow":"xtls-rprx-vision","tls":{"enabled":true,"server_name":"$target",
  "utls":{"enabled":true,"fingerprint":"chrome"},
  "reality":{"enabled":true,"public_key":"$pub","short_id":"$sid"}}}]}
EOF
	"$xray" run -c "$work/server-$ver.json" >"$work/server-$ver.log" 2>&1 &
	pids+=($!)
	"$sb" run -c "$work/client-$ver.json" >"$work/client-$ver.log" 2>&1 &
	pids+=($!)
	sleep 2

	code=000
	for _ in 1 2 3; do
		code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' -x "socks5h://127.0.0.1:$cport" \
			https://www.gstatic.com/generate_204 || true)
		[ "$code" = 204 ] && break
		sleep 2
	done
	if [ "$code" = 204 ]; then
		echo "ok    Xray $ver пускает Шлюпку"
		summary+=$'\n'"| $ver | ✅ |"
	else
		fail=1
		echo "FAIL  Xray $ver НЕ пускает Шлюпку (ответ $code)"
		sed 's/^/      /' "$work/client-$ver.log" | tail -5
		summary+=$'\n'"| $ver | ❌ не пускает |"
	fi
done

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
	echo "$summary" >>"$GITHUB_STEP_SUMMARY"
fi
exit $fail
