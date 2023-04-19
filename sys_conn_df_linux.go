//go:build linux

package quic

import (
	"errors"
	"log"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/quic-go/quic-go/internal/utils"
)

// UDP_SEGMENT controls GSO (Generic Segmentation Offload)
const UDP_SEGMENT = 103

func setDF(rawConn syscall.RawConn) error {
	// Enabling IP_MTU_DISCOVER will force the kernel to return "sendto: message too long"
	// and the datagram will not be fragmented
	var errDFIPv4, errDFIPv6 error
	if err := rawConn.Control(func(fd uintptr) {
		errDFIPv4 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO)
		errDFIPv6 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_DO)
	}); err != nil {
		return err
	}
	switch {
	case errDFIPv4 == nil && errDFIPv6 == nil:
		utils.DefaultLogger.Debugf("Setting DF for IPv4 and IPv6.")
	case errDFIPv4 == nil && errDFIPv6 != nil:
		utils.DefaultLogger.Debugf("Setting DF for IPv4.")
	case errDFIPv4 != nil && errDFIPv6 == nil:
		utils.DefaultLogger.Debugf("Setting DF for IPv6.")
	case errDFIPv4 != nil && errDFIPv6 != nil:
		return errors.New("setting DF failed for both IPv4 and IPv6")
	}
	return nil
}

func maybeSetGSO(rawConn syscall.RawConn) bool {
	var setErr error
	if err := rawConn.Control(func(fd uintptr) {
		setErr = unix.SetsockoptInt(int(fd), syscall.IPPROTO_UDP, UDP_SEGMENT, 1)
	}); err != nil {
		setErr = err
	}
	if setErr != nil {
		log.Println("failed to enable GSO")
		return false
	}
	return true
}

func isMsgSizeErr(err error) bool {
	// https://man7.org/linux/man-pages/man7/udp.7.html
	return errors.Is(err, unix.EMSGSIZE)
}
