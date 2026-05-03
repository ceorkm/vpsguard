package process

import "strings"

// Known coin-miner process names (Falco coin_miners list).
var minerNames = map[string]struct{}{
	"xmrig":          {},
	"minerd":         {},
	"moneropool":     {},
	"cryptonight":    {},
	"claymore":       {},
	"stratum":        {},
	"nicehash":       {},
	"ethminer":       {},
	"nheqminer":      {},
	"bminer":         {},
	"cgminer":        {},
	"bfgminer":       {},
	"cuda-miner":     {},
	"t-rex":          {},
	"nbminer":        {},
	"lolminer":       {},
	"nanominer":      {},
	"teamredminer":   {},
	"wildrig":        {},
	"phoenixminer":   {},
	"gminer":         {},
	"kdevtmpfsi":     {},
	"kinsing":        {},
	"watchdogs":      {},
	"sysupdate":      {},
	"networkservice": {},
	"perfctl":        {},
	"perfcc":         {},
	"kinsingd":       {},
	"system-linux":   {},
}

func baseName(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func isMiner(name string) bool {
	_, ok := minerNames[strings.ToLower(name)]
	return ok
}

func cmdlineHasMiner(cmd string) bool {
	low := strings.ToLower(cmd)
	for n := range minerNames {
		if strings.Contains(low, n) {
			return true
		}
	}
	if strings.Contains(low, "stratum+tcp://") || strings.Contains(low, "stratum+ssl://") {
		return true
	}
	return false
}

func isShell(name string) bool {
	switch strings.ToLower(name) {
	case "sh", "bash", "dash", "zsh", "ksh", "ash":
		return true
	}
	return false
}

func isWebProcess(name string) bool {
	low := strings.ToLower(name)
	for _, needle := range []string{
		"nginx", "apache", "apache2", "httpd", "php-fpm", "php",
		"node", "gunicorn", "uwsgi", "puma", "passenger", "ruby",
		"python", "perl", "cgi",
	} {
		if strings.Contains(low, needle) {
			return true
		}
	}
	return false
}

func suspiciousEnv(env string) string {
	low := strings.ToLower(env)
	switch {
	case strings.Contains(low, "ld_preload="):
		return "ld_preload"
	case strings.Contains(low, "histfile=/dev/null"):
		return "histfile_dev_null"
	case strings.Contains(low, "histsize=0"):
		return "histsize_zero"
	case strings.Contains(low, "histfile=/tmp/"):
		return "histfile_tmp"
	}
	return ""
}

func suspiciousCommand(cmd string) string {
	low := strings.ToLower(cmd)
	switch {
	case strings.Contains(low, "/dev/tcp/") && (strings.Contains(low, "bash") || strings.Contains(low, "sh")):
		return "dev_tcp_reverse_shell"
	case strings.Contains(low, " nc ") && (strings.Contains(low, " -e ") || strings.Contains(low, " -c ")):
		return "netcat_exec"
	case strings.Contains(low, "ncat ") && (strings.Contains(low, " --exec ") || strings.Contains(low, " -e ")):
		return "ncat_exec"
	case strings.Contains(low, "socat ") && strings.Contains(low, "exec:"):
		return "socat_exec"
	case strings.Contains(low, "masscan ") || strings.Contains(low, "zmap "):
		return "internet_scan_tool"
	case downloaderPipeShell(low):
		return "downloader_piped_to_shell"
	case encodedShellPayload(low):
		return "encoded_shell_payload"
	case strings.Contains(low, ".onion") && (strings.Contains(low, "torsocks") || strings.Contains(low, "tor ")):
		return "tor_onion_downloader"
	case strings.Contains(low, "docker ") && (strings.Contains(low, "-v /:/host") || strings.Contains(low, "--privileged") || strings.Contains(low, "/var/run/docker.sock")):
		return "suspicious_docker_host_access"
	case strings.Contains(low, "xclip") || strings.Contains(low, "xsel ") || strings.Contains(low, "wl-paste"):
		return "clipboard_access"
	}
	return ""
}

func downloaderPipeShell(low string) bool {
	hasDownloader := strings.Contains(low, "curl ") || strings.Contains(low, "wget ")
	hasShell := strings.Contains(low, "| sh") || strings.Contains(low, "|sh") ||
		strings.Contains(low, "| bash") || strings.Contains(low, "|bash")
	return hasDownloader && hasShell
}

func encodedShellPayload(low string) bool {
	hasDecode := strings.Contains(low, "base64 -d") || strings.Contains(low, "base64 --decode") ||
		strings.Contains(low, "python -c") || strings.Contains(low, "python3 -c") ||
		strings.Contains(low, "perl -e")
	hasShell := strings.Contains(low, "| sh") || strings.Contains(low, "| bash") ||
		strings.Contains(low, "sh -c") || strings.Contains(low, "bash -c")
	return hasDecode && hasShell
}
