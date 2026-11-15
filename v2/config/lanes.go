package config

// Полосы групп «Шлюпки спасения» (docs: приложение, раздельный туннель, группы).
//
// Через VPN всё идёт по одному соединению с сервером (у gRPC — одно HTTP/2-соединение на выход).
// Когда что-то качается, пакеты Discord или игры ждут в той же очереди: пинг прыгает до секунд.
// Полоса — отдельный выход к тому же серверу, то есть своё соединение. Приложение раскладывает
// записи групп «через VPN» по файлам via-lane-<n>.json, ядро ведёт каждый файл в свою полосу.
//
// Полос всегда LaneCount, число групп у пользователя меняется на лету: файлы перечитываются без
// переподключения, а пустая полоса соединений не открывает (выход подключается при первом
// запросе). Полоса — селектор из копий серверов `select`; копия получает тег
// «<сервер> §laneN§ §hide§». Endpoint'ы (WireGuard, AmneziaWG) не копируются: второй экземпляр с
// тем же ключом сломал бы первый, поэтому в полосе стоит сам endpoint. Какой сервер выбран в
// полосе, ведёт служба rescuestats.LaneSync: та же, что сейчас в `select`.

import (
	"fmt"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// LaneCount — сколько полос у ядра. Групп «через VPN» больше — остальные идут общим путём.
const LaneCount = 8

// LaneMarker есть в теге каждой копии сервера: проверка пинга ядра такие выходы пропускает
// (заплатка 0004), иначе она держала бы открытыми соединения всех копий.
const LaneMarker = "§lane"

// LaneTag — тег селектора полосы n.
func LaneTag(n int) string { return fmt.Sprintf("rescue-lane-%d §hide§", n) }

// LaneCopyTag — тег копии сервера tag в полосе n.
func LaneCopyTag(tag string, n int) string {
	return fmt.Sprintf("%s %s%d§ §hide§", tag, LaneMarker, n)
}

// IsLaneTag — выход служебный для полос (селектор или копия).
func IsLaneTag(tag string) bool {
	return strings.Contains(tag, LaneMarker) || strings.HasPrefix(tag, "rescue-lane-")
}

// addLanes добавляет копии серверов и селекторы полос. Возвращает теги селекторов (пусто —
// полос нет: нет серверов).
func addLanes(options *option.Options) []string {
	servers := selectServers(options)
	if len(servers) == 0 {
		return nil
	}
	byTag := make(map[string]option.Outbound, len(options.Outbounds))
	for _, out := range options.Outbounds {
		byTag[out.Tag] = out
	}
	var copies []option.Outbound
	var lanes []option.Outbound
	var tags []string
	for n := 0; n < LaneCount; n++ {
		members := make([]string, 0, len(servers))
		for _, tag := range servers {
			out, isOutbound := byTag[tag]
			if !isOutbound {
				members = append(members, tag) // endpoint: сам, без копии
				continue
			}
			cp := out
			cp.Tag = LaneCopyTag(tag, n)
			copies = append(copies, cp)
			members = append(members, cp.Tag)
		}
		tag := LaneTag(n)
		tags = append(tags, tag)
		lanes = append(lanes, option.Outbound{
			Type: C.TypeSelector,
			Tag:  tag,
			Options: &option.SelectorOutboundOptions{
				Outbounds:                 members,
				Default:                   members[0],
				InterruptExistConnections: true,
			},
		})
	}
	options.Outbounds = append(options.Outbounds, lanes...)
	options.Outbounds = append(options.Outbounds, copies...)
	return tags
}
