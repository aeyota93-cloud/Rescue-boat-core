//go:build !windows

package rescuestats

import (
	"net/netip"
	"time"
)

// nativePing: на этой ОС своего системного вызова нет — используется сокет.
func nativePing(ip netip.Addr, timeout time.Duration) (time.Duration, bool, error) {
	return 0, false, nil
}
