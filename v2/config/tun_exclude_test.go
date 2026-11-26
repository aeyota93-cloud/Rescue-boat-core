package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestTunExcludeAddresses(t *testing.T) {
	dir := t.TempDir()
	text := "# сети Blizzard\n" +
		"137.221.64.0/22\n" +
		"35.228.147.76   # игра\n" +
		"35.228.147.76\n" + // повтор
		"\n" +
		"not-an-ip\n" +
		"0.0.0.0/0\n" + // весь интернет — нельзя
		"10.0.0.0/8\n" + // локальная сеть
		"192.168.1.1\n" +
		"127.0.0.1\n" +
		"224.0.0.1\n" +
		"1.2.3.4/33\n" +
		"5.42.160.7/20\n" + // нормализуется до сети
		"2a00:1450::1\n"
	if err := os.WriteFile(filepath.Join(dir, tunExcludeFile), []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	got := tunExcludeAddresses(dir)
	want := []netip.Prefix{
		netip.MustParsePrefix("137.221.64.0/22"),
		netip.MustParsePrefix("35.228.147.76/32"),
		netip.MustParsePrefix("5.42.160.0/20"),
		netip.MustParsePrefix("2a00:1450::1/128"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestTunExcludeAddressesMissing(t *testing.T) {
	if got := tunExcludeAddresses(t.TempDir()); got != nil {
		t.Fatalf("no file: got %v", got)
	}
	if got := tunExcludeAddresses(""); got != nil {
		t.Fatalf("no dir: got %v", got)
	}
}

func TestTunExcludeInInbound(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, tunExcludeFile), []byte("34.88.131.44\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var options option.Options
	hopt := &HiddifyOptions{SplitTunnelDir: dir}
	hopt.EnableTun = true
	setInbound(&options, hopt)
	for _, in := range options.Inbounds {
		if in.Tag != InboundTUNTag {
			continue
		}
		opts := in.Options.(*option.TunInboundOptions)
		if len(opts.RouteExcludeAddress) != 1 || opts.RouteExcludeAddress[0] != netip.MustParsePrefix("34.88.131.44/32") {
			t.Fatalf("route_exclude_address = %v", opts.RouteExcludeAddress)
		}
		return
	}
	t.Fatal("no tun inbound")
}
