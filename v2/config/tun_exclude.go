package config

// Шлюпка: адреса мимо туннеля.
//
// Приложение пишет в SplitTunnelDir файл tun-exclude.txt: по адресу или сети в строке
// («35.228.147.76», «137.221.64.0/22»), строки с «#» — комментарии. Эти адреса ядро убирает из
// маршрутов TUN (route_exclude_address): Windows отправляет пакеты к ним сразу в сетевую карту, и
// они вообще не проходят через ядро. Так игра не ждёт ядро, когда процессор занят.
//
// Это не правило маршрутизации ядра, а таблица маршрутов Windows: она различает только адрес, не
// программу, и читается один раз при подключении. Поэтому список узкий (сети Blizzard и адреса,
// куда ходила игра), а новые адреса начинают работать со следующего подключения.

import (
	"bufio"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

const (
	tunExcludeFile = "tun-exclude.txt"
	// Каждый адрес дробит маршрут 0.0.0.0/0 примерно на 30 маршрутов, а Windows добавляет их по
	// одному: тысяча адресов — это уже заметная пауза при подключении.
	tunExcludeMax = 1024
)

// tunExcludeAddresses читает tun-exclude.txt из dir. Нет файла или папки — пустой список.
// Плохие строки и слишком широкие сети (шире /8 для IPv4, /16 для IPv6), а также локальные и
// служебные адреса пропускаются: случайная ошибка в файле не должна вывести мимо VPN весь трафик.
func tunExcludeAddresses(dir string) []netip.Prefix {
	if dir == "" {
		return nil
	}
	f, err := os.Open(filepath.Join(dir, tunExcludeFile))
	if err != nil {
		return nil
	}
	defer f.Close()
	seen := make(map[netip.Prefix]bool)
	var res []netip.Prefix
	scanner := bufio.NewScanner(f)
	for scanner.Scan() && len(res) < tunExcludeMax {
		line := scanner.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		p, ok := parseTunExclude(strings.TrimSpace(line))
		if !ok || seen[p] {
			continue
		}
		seen[p] = true
		res = append(res, p)
	}
	return res
}

func parseTunExclude(s string) (netip.Prefix, bool) {
	if s == "" {
		return netip.Prefix{}, false
	}
	var p netip.Prefix
	if strings.Contains(s, "/") {
		var err error
		if p, err = netip.ParsePrefix(s); err != nil {
			return netip.Prefix{}, false
		}
	} else {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, false
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	p = p.Masked()
	a := p.Addr()
	if a.Is4In6() || a.Zone() != "" {
		return netip.Prefix{}, false
	}
	minBits := 8
	if a.Is6() {
		minBits = 16
	}
	if p.Bits() < minBits || !a.IsGlobalUnicast() || a.IsPrivate() {
		return netip.Prefix{}, false
	}
	return p, true
}
