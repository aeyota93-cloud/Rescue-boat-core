//go:build windows

package rescuestats

import (
	"errors"
	"net/netip"
	"syscall"
	"time"
	"unsafe"
)

var (
	iphlpapi       = syscall.NewLazyDLL("iphlpapi.dll")
	procIcmpCreate = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpClose  = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSend   = iphlpapi.NewProc("IcmpSendEcho")
)

// icmpEchoReply — ICMP_ECHO_REPLY из icmpapi.h (64-битная раскладка).
type icmpEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          uintptr
	TTL           uint8
	TOS           uint8
	Flags         uint8
	OptionsSize   uint8
	OptionsData   uintptr
}

const (
	ipSuccess      = 0
	errIPReqTimeOu = 11010 // IP_REQ_TIMED_OUT
)

// nativePing — IcmpSendEcho (только IPv4): работает без прав администратора. IPv6 — через сокет.
func nativePing(ip netip.Addr, timeout time.Duration) (time.Duration, bool, error) {
	ip = ip.Unmap()
	if !ip.Is4() {
		return 0, false, nil
	}
	h, _, callErr := procIcmpCreate.Call()
	if h == 0 || h == ^uintptr(0) {
		return 0, false, nil // не вышло — пробуем сокет
	}
	defer procIcmpClose.Call(h)

	b := ip.As4()
	dest := uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
	data := []byte("prichal-compare")
	reply := make([]byte, int(unsafe.Sizeof(icmpEchoReply{}))+len(data)+8)
	start := time.Now()
	ret, _, callErr := procIcmpSend.Call(
		h,
		uintptr(dest),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		0,
		uintptr(unsafe.Pointer(&reply[0])),
		uintptr(len(reply)),
		uintptr(timeout/time.Millisecond),
	)
	elapsed := time.Since(start)
	if ret == 0 {
		if errno, ok := callErr.(syscall.Errno); ok && errno == errIPReqTimeOu {
			return 0, true, errors.New("таймаут")
		}
		return 0, true, callErr
	}
	r := (*icmpEchoReply)(unsafe.Pointer(&reply[0]))
	if r.Status != ipSuccess {
		return 0, true, errors.New("нет ответа")
	}
	if elapsed < time.Millisecond {
		elapsed = time.Millisecond
	}
	return elapsed, true, nil
}
