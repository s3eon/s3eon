package s3proxy

import (
	"errors"
	"net"
	"net/http"
	"strings"
)

type ipExtractor struct {
	nets []*net.IPNet
}

func newIPExtractor(whitelist []string) (*ipExtractor, error) {
	var nets []*net.IPNet
	for _, s := range whitelist {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}

		if strings.Contains(s, "/") {
			_, netw, err := net.ParseCIDR(s)
			if err != nil {
				return nil, err
			}
			nets = append(nets, netw)
			continue
		}

		ip := net.ParseIP(s)
		if ip == nil {
			return nil, errors.New("invalid whitelist entry: " + s)
		}
		var netw *net.IPNet
		if ip.To4() != nil {
			netw = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
		} else {
			netw = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
		}
		nets = append(nets, netw)
	}

	return &ipExtractor{nets: nets}, nil
}

func (e *ipExtractor) ExtractClientIP(r *http.Request) string {
	remoteIP := ipFromRemoteAddr(r.RemoteAddr)
	if remoteIP == nil {
		return r.RemoteAddr
	}

	if !e.isWhitelisted(remoteIP) {
		return remoteIP.String()
	}

	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if ip := parseMaybeWithPort(p); ip != nil {
				return ip.String()
			}
		}
	}

	real := strings.TrimSpace(r.Header.Get("X-Real-IP"))
	if real != "" {
		if ip := parseMaybeWithPort(real); ip != nil {
			return ip.String()
		}
	}

	return remoteIP.String()
}

func (e *ipExtractor) isWhitelisted(ip net.IP) bool {
	if e == nil {
		return false
	}
	for _, n := range e.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func ipFromRemoteAddr(remote string) net.IP {
	if remote == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}

	if i := strings.LastIndex(host, "%"); i != -1 {
		host = host[:i]
	}
	return net.ParseIP(host)
}

func parseMaybeWithPort(s string) net.IP {
	h, _, err := net.SplitHostPort(s)
	if err == nil {
		if i := strings.LastIndex(h, "%"); i != -1 {
			h = h[:i]
		}
		return net.ParseIP(h)
	}

	if i := strings.LastIndex(s, "%"); i != -1 {
		s = s[:i]
	}
	return net.ParseIP(s)
}
