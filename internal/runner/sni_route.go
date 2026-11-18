package runner

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// checkCaptureRoute asks the kernel which local address it would use for the
// endpoint. Connecting a UDP socket without writing sends no datagram.
func checkCaptureRoute(ctx context.Context, ifaceName, ip string, port int) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("capture interface: %w", err)
	}
	if err := checkCaptureLinkType(filepath.Join("/sys/class/net", iface.Name, "type")); err != nil {
		return err
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp4", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return fmt.Errorf("resolve local route: %w", err)
	}
	defer func() { _ = conn.Close() }()
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return fmt.Errorf("resolve local route: unexpected local address")
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return fmt.Errorf("capture interface addresses: %w", err)
	}
	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err == nil && ip.Equal(local.IP) {
			return nil
		}
	}
	return fmt.Errorf("capture interface %s does not own route source %s", ifaceName, local.IP)
}

func checkCaptureLinkType(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("capture link type: %w", err)
	}
	switch strings.TrimSpace(string(data)) {
	case "1", "772": // Linux ARPHRD_ETHER and ARPHRD_LOOPBACK.
		return nil
	default:
		return fmt.Errorf("capture link type %q is unsupported", strings.TrimSpace(string(data)))
	}
}
