package capability

import (
	"encoding/xml"
	"fmt"
	"net"
	"strings"

	"github.com/s41r4j/cybot/pkg/schema"
)

// parseNmap matches the XML selected by nmapArgs (-oX -).
func parseNmap(data []byte, _ schema.RunRequest) (schema.Result, error) {
	var report struct {
		XMLName xml.Name `xml:"nmaprun"`
		Hosts   []struct {
			Status struct {
				State string `xml:"state,attr"`
			} `xml:"status"`
			Addresses []struct {
				Addr string `xml:"addr,attr"`
				Type string `xml:"addrtype,attr"`
			} `xml:"address"`
			Names []struct {
				Name string `xml:"name,attr"`
			} `xml:"hostnames>hostname"`
			Ports []struct {
				ID       int    `xml:"portid,attr"`
				Protocol string `xml:"protocol,attr"`
				State    struct {
					State string `xml:"state,attr"`
				} `xml:"state"`
				Service struct {
					Name    string `xml:"name,attr"`
					Product string `xml:"product,attr"`
					Version string `xml:"version,attr"`
				} `xml:"service"`
			} `xml:"ports>port"`
		} `xml:"host"`
		Finished struct {
			Exit  string `xml:"exit,attr"`
			Error string `xml:"errormsg,attr"`
		} `xml:"runstats>finished"`
	}
	r := emptyResult()
	if err := xml.Unmarshal(data, &report); err != nil {
		return r, fmt.Errorf("nmap XML: %w", err)
	}
	if report.Finished.Exit == "error" {
		return r, fmt.Errorf("nmap failed: %s", report.Finished.Error)
	}
	for _, host := range report.Hosts {
		if host.Status.State == "down" {
			continue
		}
		address := ""
		for _, a := range host.Addresses {
			if (a.Type != "ipv4" && a.Type != "ipv6") || net.ParseIP(a.Addr) == nil {
				continue
			}
			if address == "" {
				address = a.Addr
			}
			r.Assets = append(r.Assets, schema.Asset{Value: a.Addr, Type: a.Type, Source: "nmap", Confidence: .9})
		}
		for _, n := range host.Names {
			if validateHostname(n.Name) == nil {
				r.Assets = append(r.Assets, schema.Asset{Value: n.Name, Type: "hostname", Source: "nmap", Confidence: .85})
			}
		}
		for _, p := range host.Ports {
			if p.State.State != "open" || address == "" {
				continue
			}
			if p.ID < 1 || p.ID > 65535 {
				return r, fmt.Errorf("nmap returned invalid port %d", p.ID)
			}
			r.Services = append(r.Services, schema.Service{Host: address, Port: p.ID, Protocol: p.Protocol, Technology: strings.TrimSpace(p.Service.Name + " " + p.Service.Product + " " + p.Service.Version), Confidence: .85})
		}
	}
	deduplicateResult(&r)
	return r, nil
}
