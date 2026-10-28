package capability

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/s41r4j/cybot/pkg/schema"
)

var interfaceName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

func toolScope(tool string) string {
	switch tool {
	case "bettercap", "responder":
		return "interface"
	case "mimikatz", "linpeas", "winpeas", "seatbelt", "sharpup":
		return "local"
	default:
		return "target"
	}
}

// Local and interface-wide operations must name the resource they actually
// inspect. A remote hostname cannot authorize operations on the executing host.
func validateStepScope(tool string, req schema.RunRequest) error {
	if err := validateStepTarget(tool, req.Target); err != nil {
		return err
	}
	if toolScope(tool) != "target" && !req.Approved {
		return fmt.Errorf("%s requires explicit approval of the %s resource even in suggestive policy mode", tool, toolScope(tool))
	}
	return nil
}

func validateStepTarget(tool, target string) error {
	scope := toolScope(tool)
	if scope == "target" {
		return nil
	}
	u, err := url.Parse(target)
	if err != nil || u.Scheme != scope || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Port() != "" {
		return fmt.Errorf("%s requires an explicit %s://RESOURCE target; a remote target does not authorize this operation", tool, scope)
	}
	if scope == "interface" && !interfaceName.MatchString(u.Host) {
		return fmt.Errorf("invalid network interface name")
	}
	if scope == "local" {
		host, err := os.Hostname()
		if err != nil || !strings.EqualFold(u.Host, host) {
			return fmt.Errorf("%s must name the executing machine as local://HOSTNAME", tool)
		}
	}
	return nil
}

func scopedResource(target string) string {
	u, err := url.Parse(target)
	if err == nil && (u.Scheme == "interface" || u.Scheme == "local") {
		return u.Host
	}
	return target
}
