package source

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const MaxDocumentBytes int64 = 10 << 20

func Fetch(ctx context.Context, rawURL string) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return nil, fmt.Errorf("remote imports require an absolute HTTPS URL without credentials")
	}
	if err = validateHost(ctx, u.Hostname()); err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Environment proxies can resolve destinations themselves and bypass the
	// address restriction. Imports use direct TLS with the original hostname.
	transport.Proxy = nil
	transport.DialTLSContext = nil
	transport.DialContext = publicDial(net.DefaultResolver.LookupIPAddr, (&net.Dialer{Timeout: 10 * time.Second}).DialContext)
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 30 * time.Second, Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 5 {
			return fmt.Errorf("too many redirects")
		}
		if req.URL.Scheme != "https" || req.URL.User != nil {
			return fmt.Errorf("redirect to non-HTTPS URL or embedded credentials denied")
		}
		return validateHost(req.Context(), req.URL.Hostname())
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "cybot-source-import/1")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("source returned HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > MaxDocumentBytes {
		return nil, fmt.Errorf("source exceeds %d bytes", MaxDocumentBytes)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxDocumentBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > MaxDocumentBytes {
		return nil, fmt.Errorf("source exceeds %d bytes", MaxDocumentBytes)
	}
	return b, nil
}
func validateHost(ctx context.Context, host string) error {
	_, err := publicIPs(ctx, host, net.DefaultResolver.LookupIPAddr)
	return err
}

type lookupIPs func(context.Context, string) ([]net.IPAddr, error)
type dialAddress func(context.Context, string, string) (net.Conn, error)

func publicIPs(ctx context.Context, host string, lookup lookupIPs) ([]net.IPAddr, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") {
		return nil, fmt.Errorf("local source hosts are denied")
	}
	ips, err := lookup(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve source host: %w", err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("source host resolved to no addresses")
	}
	for _, entry := range ips {
		ip := entry.IP
		v4 := ip.To4()
		shared := v4 != nil && (v4[0] == 0 || v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127)
		if entry.Zone != "" || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || shared {
			return nil, fmt.Errorf("private or local source address is denied")
		}
	}
	return ips, nil
}

// Resolve once per connection, validate every answer, and dial the validated
// numeric address. The transport still uses the URL hostname for TLS/SNI.
func publicDial(lookup lookupIPs, dial dialAddress) dialAddress {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ips, err := publicIPs(ctx, host, lookup)
		if err != nil {
			return nil, err
		}
		var last error
		for _, ip := range ips {
			conn, err := dial(ctx, network, net.JoinHostPort(ip.IP.String(), port))
			if err == nil {
				return conn, nil
			}
			last = err
		}
		return nil, fmt.Errorf("connect to approved source address: %w", last)
	}
}
