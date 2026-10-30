#!/usr/bin/env bash
# Сторож совместимости: пускает ли сервер Xray (Reality) клиента — ядро Шлюпки (sing-box с
# patches/hiddify-sing-box). Так 30.10.2026 узнали поздно: Xray 26.9.8+ перестал пускать sing-box.
#
#   scripts/xray-compat.sh <sing-box> <xray> [<xray> ...]
#
# На каждый xray и каждый транспорт (vision — VLESS Reality «как раньше», grpc — рабочий путь
# сервера с 31.10.2026): одноразовые ключи, сервер и клиент на 127.0.0.1, запрос через туннель.
# Код выхода 1, если хоть одна пара не прошла. Нужны curl и openssl; ходит в интернет.
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

# Запрос через туннель клиента. -q и --noproxy '': переменные окружения (NO_PROXY=* и т.п.)
# не должны пустить curl мимо туннеля — это был бы ложный «ok».
probe() {
	curl -q -s -m 10 --noproxy '' -o /dev/null -w '%{http_code}' -x "socks5h://127.0.0.1:$1" \
		https://www.gstatic.com/generate_204 || true
}

fail=0
port=24000
summary="| Xray | транспорт | Шлюпка (chrome) |"$'\n'"|---|---|---|"
for xray in "$@"; do
	ver=$("$xray" version | head -1 | awk '{print $2}')
	keys=$("$xray" x25519)
	# Старый вывод: «Private key / Public key», новый: «PrivateKey / Password (PublicKey)».
	priv=$(grep -i -m1 'private' <<<"$keys" | awk -F': *' '{print $2}')
	pub=$(grep -i -m1 -E 'public|password' <<<"$keys" | awk -F': *' '{print $2}')
	sid=$(openssl rand -hex 8)
	uid=$(cat /proc/sys/kernel/random/uuid)

	for mode in vision grpc; do
		sport=$port
		cport=$((port + 1))
		port=$((port + 2))
		if [ "$mode" = vision ]; then
			sflow=',"flow":"xtls-rprx-vision"'
			snet='"network":"raw"'
			cextra=',"flow":"xtls-rprx-vision"'
		else
			sflow=''
			snet='"network":"grpc","grpcSettings":{"serviceName":"compat"}'
			cextra=',"transport":{"type":"grpc","service_name":"compat"}'
		fi
		name="$ver-$mode"

		cat >"$work/server-$name.json" <<EOF
{"log":{"loglevel":"warning"},
 "inbounds":[{"listen":"127.0.0.1","port":$sport,"protocol":"vless",
  "settings":{"clients":[{"id":"$uid"$sflow}],"decryption":"none"},
  "streamSettings":{$snet,"security":"reality","realitySettings":{
   "target":"$target:443","serverNames":["$target"],"privateKey":"$priv","shortIds":["$sid"]}}}],
 "outbounds":[{"protocol":"freedom"}]}
EOF
		cat >"$work/client-$name.json" <<EOF
{"log":{"level":"error"},
 "inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":$cport}],
 "outbounds":[{"type":"vless","server":"127.0.0.1","server_port":$sport,"uuid":"$uid"$cextra,
  "tls":{"enabled":true,"server_name":"$target",
  "utls":{"enabled":true,"fingerprint":"chrome"},
  "reality":{"enabled":true,"public_key":"$pub","short_id":"$sid"}}}]}
EOF
		"$xray" run -c "$work/server-$name.json" >"$work/server-$name.log" 2>&1 &
		pids+=($!)
		"$sb" run -c "$work/client-$name.json" >"$work/client-$name.log" 2>&1 &
		pids+=($!)
		sleep 2

		code=000
		for _ in 1 2 3; do
			code=$(probe "$cport")
			[ "$code" = 204 ] && break
			sleep 2
		done
		if [ "$code" = 204 ]; then
			echo "ok    Xray $ver ($mode) пускает Шлюпку"
			summary+=$'\n'"| $ver | $mode | ✅ |"
		else
			fail=1
			echo "FAIL  Xray $ver ($mode) НЕ пускает Шлюпку (ответ $code)"
			sed 's/^/      /' "$work/client-$name.log" | tail -5
			summary+=$'\n'"| $ver | $mode | ❌ не пускает |"
		fi
	done

	# Обратная проверка: тот же сервер, клиент с чужим ключом Reality — должен НЕ пройти.
	# Если проходит, проверка выше ничего не доказывает (запрос идёт мимо Reality).
	badkeys=$("$xray" x25519)
	badpub=$(grep -i -m1 -E 'public|password' <<<"$badkeys" | awk -F': *' '{print $2}')
	sed "s#\"public_key\":\"$pub\"#\"public_key\":\"$badpub\"#" "$work/client-$ver-vision.json" >"$work/client-$ver-bad.json"
	bport=$port
	port=$((port + 2))
	sed -i "s#\"listen_port\":[0-9]*#\"listen_port\":$bport#" "$work/client-$ver-bad.json"
	"$sb" run -c "$work/client-$ver-bad.json" >"$work/client-$ver-bad.log" 2>&1 &
	pids+=($!)
	sleep 2
	if [ "$(probe "$bport")" = 204 ]; then
		fail=1
		echo "FAIL  Xray $ver: клиент с чужим ключом тоже прошёл — проверка недостоверна"
		summary+=$'\n'"| $ver | чужой ключ | ❌ прошёл (проверка недостоверна) |"
	else
		echo "ok    Xray $ver: чужой ключ не пускает (проверка достоверна)"
		summary+=$'\n'"| $ver | чужой ключ | ✅ не пускает |"
	fi
done

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
	echo "$summary" >>"$GITHUB_STEP_SUMMARY"
fi
exit $fail
