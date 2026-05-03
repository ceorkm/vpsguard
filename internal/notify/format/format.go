// Package format converts Event structs into Telegram MarkdownV2 messages.
//
// Templates are derived from PRD section 23 ("Example alert library").
// Goal: every alert reads in plain English, with the user's server label
// up top and the actionable detail clearly highlighted.
package format

import (
	"fmt"
	"strings"
	"time"

	"github.com/ceorkm/vpsguard/internal/event"
	"github.com/ceorkm/vpsguard/internal/notify/telegram"
)

// Format returns a MarkdownV2 string suitable for Telegram sendMessage.
// Type-specific formatters fall back to a generic layout if no specific
// template exists for the event type.
func Format(e *event.Event) string {
	if e == nil {
		return ""
	}
	switch e.Type {
	case event.TypeSSHLoginSuccess:
		return formatSSHLogin(e)
	case event.TypeSSHLoginFailed, event.TypeSSHInvalidUser:
		return formatSSHFailed(e)
	case event.TypeSSHBruteforce:
		return formatBruteforce(e)
	case event.TypeProcessKnownMiner:
		return formatMiner(e)
	case event.TypeProcessHighCPU:
		return formatHighCPUProcess(e)
	case event.TypeProcessWebShell:
		return formatSuspiciousProcess(e)
	case event.TypeProcessEnvTamper:
		return formatSuspiciousProcess(e)
	case event.TypeProcessSuspicious:
		return formatSuspiciousProcess(e)
	case event.TypeProcessCredAccess:
		return formatSuspiciousProcess(e)
	case event.TypeProcessTmpOutbound:
		return formatSuspiciousProcess(e)
	case event.TypeProcessReinfection:
		return formatReinfection(e)
	case event.TypeCPUSpike:
		return formatCPUSpike(e)
	case event.TypeOutboundSSHSpike:
		return formatOutbound(e, "🚨 *Possible outbound SSH abuse*",
			"Your VPS may be attacking other servers over SSH.")
	case event.TypeOutboundSMTPSpike:
		return formatOutbound(e, "🚨 *Possible outbound SMTP abuse*",
			"Your VPS may be relaying spam or probing mail servers.")
	case event.TypeOutboundRDPSpike:
		return formatOutbound(e, "🚨 *Possible outbound RDP abuse*",
			"Your VPS may be attacking Windows hosts over RDP.")
	case event.TypeOutboundMinerPool:
		return formatOutbound(e, "🚨 *Possible mining pool connection*",
			"Common miner pool ports were observed from this server.")
	case event.TypeCloudMetadataAccess:
		return formatOutbound(e, "🚨 *Cloud metadata access*",
			"A process contacted the cloud metadata service; investigate possible credential theft.")
	case event.TypeOutboundBulkTransfer:
		return formatOutbound(e, "🚨 *High outbound transfer*",
			"The VPS transmitted an unusual amount of outbound data.")
	case event.TypeServiceExposed:
		return formatOutbound(e, "🚨 *Risky public service exposed*",
			"Review this listening service; VpsGuard alerts only and does not change firewall rules.")
	case event.TypeKnownBadConnection:
		return formatOutbound(e, "🚨 *Known\\-bad IP contacted*",
			"This VPS opened a connection to an IP/CIDR listed in known\\_bad\\_ips.")
	case event.TypeKnownBadDomain:
		return formatOutbound(e, "🚨 *Known\\-bad domain queried*",
			"This VPS queried a domain listed in known\\_bad\\_domains.")
	case event.TypeDNSAnomaly:
		return formatOutbound(e, "🚨 *Possible DNS tunneling*",
			"Resolver logs show repeated long or encoded subdomain queries.")
	case event.TypeCronModified:
		return formatFileChange(e, "🚨 *New or modified cron job*",
			"Cron jobs are commonly used by attackers for persistence.")
	case event.TypeSSHKeyAdded:
		return formatFileChange(e, "🚨 *SSH key file changed*",
			"A new key in authorized\\_keys can grant attackers persistent access.")
	case event.TypeUserCreated:
		return formatFileChange(e, "🚨 *Identity file changed*",
			"User accounts may have been added or modified.")
	case event.TypeSudoerModified:
		return formatFileChange(e, "🚨 *Sudoers file changed*",
			"Privilege grants may have been altered.")
	case event.TypeSystemdServiceAdded:
		return formatFileChange(e, "🚨 *System file changed*",
			"Attackers commonly add systemd units or modify linker preload for persistence.")
	case event.TypeAgentStarted:
		return formatAgent(e, "ℹ️ *vpsguard started*", "")
	case event.TypeAgentStopped:
		return formatAgent(e, "ℹ️ *vpsguard stopping*", "")
	case event.TypeAgentError:
		return formatAgentError(e)
	case event.TypeAgentBinaryModified:
		return formatTamper(e)
	case event.TypeServiceBruteforce:
		return formatBruteforce(e)
	case event.TypeAuditSetuid, event.TypeAuditKernelModule, event.TypeAuditSensitiveFile,
		event.TypeRootkitSuspicious, event.TypeFIMModified, event.TypeRansomwareActivity:
		return formatGeneric(e)
	}
	return formatGeneric(e)
}

// emojiFor maps severity to a leading emoji.
func emojiFor(s event.Severity) string {
	switch s {
	case event.SevCritical:
		return "🚨"
	case event.SevHigh:
		return "🚨"
	case event.SevMedium:
		return "⚠️"
	case event.SevLow:
		return "ℹ️"
	default:
		return "ℹ️"
	}
}

func esc(s string) string { return telegram.EscapeMarkdownV2(s) }

// escCode escapes for content inside `code` spans. Per Telegram spec,
// only backtick and backslash need escaping inside code; the wider
// MarkdownV2 reserved set does not apply.
func escCode(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 4)
	for _, r := range s {
		if r == '`' || r == '\\' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// fieldCode fetches a string field formatted for inline-code use.
func fieldCode(e *event.Event, key string) string {
	v, ok := e.Fields[key]
	if !ok {
		return ""
	}
	switch x := v.(type) {
	case string:
		return escCode(x)
	default:
		return escCode(fmt.Sprintf("%v", x))
	}
}

// fieldStr fetches a string field, escaped for MarkdownV2. Returns ""
// if missing.
func fieldStr(e *event.Event, key string) string {
	v, ok := e.Fields[key]
	if !ok {
		return ""
	}
	switch x := v.(type) {
	case string:
		return esc(x)
	case fmt.Stringer:
		return esc(x.String())
	default:
		return esc(fmt.Sprintf("%v", x))
	}
}

func headerLines(e *event.Event, title string) []string {
	lines := []string{title}
	if e.Server != "" {
		lines = append(lines, "*Server:* "+esc(e.Server))
	}
	if e.Fields != nil {
		if id, ok := e.Fields["incident_id"]; ok {
			lines = append(lines, "*Incident:* "+esc(fmt.Sprintf("%v", id)))
		}
	}
	return lines
}

func footer(e *event.Event) string {
	return "*Time:* " + esc(e.Time.UTC().Format("2006-01-02 15:04 UTC"))
}

func join(parts []string) string {
	return strings.Join(parts, "\n")
}

// --- per-type formatters ---

func formatSSHLogin(e *event.Event) string {
	user := fieldStr(e, "user")
	ip := fieldStr(e, "ip")
	title := fmt.Sprintf("%s *New SSH login*", emojiFor(e.Severity))
	parts := headerLines(e, title)
	if user != "" {
		parts = append(parts, "*User:* "+user)
	}
	if ip != "" {
		parts = append(parts, "*IP:* "+ip)
	}
	if method := fieldStr(e, "method"); method != "" {
		parts = append(parts, "*Method:* "+method)
	}
	if first := fieldStr(e, "first_seen"); first == "true" {
		parts = append(parts, "This IP has never logged into this server before.")
	}
	parts = append(parts, "*Detail:* "+esc(e.Title))
	parts = append(parts, footer(e))
	return join(parts)
}

func formatSSHFailed(e *event.Event) string {
	user := fieldStr(e, "user")
	ip := fieldStr(e, "ip")
	emoji := emojiFor(e.Severity)
	parts := headerLines(e, fmt.Sprintf("%s *SSH login failed*", emoji))
	if user != "" {
		parts = append(parts, "*User:* "+user)
	}
	if ip != "" {
		parts = append(parts, "*IP:* "+ip)
	}
	parts = append(parts, "*Detail:* "+esc(e.Title))
	parts = append(parts, footer(e))
	return join(parts)
}

func formatBruteforce(e *event.Event) string {
	parts := headerLines(e, "🚨 *SSH brute\\-force attack detected*")
	if ip := fieldStr(e, "ip"); ip != "" {
		parts = append(parts, "*IP:* "+ip)
	}
	if attempts := fieldStr(e, "failed_attempts"); attempts != "" {
		parts = append(parts, "*Failed attempts:* "+attempts)
	}
	if window := fieldStr(e, "window"); window != "" {
		parts = append(parts, "*Window:* "+window)
	}
	parts = append(parts, "*Recommended:* review source and confirm Fail2Ban coverage")
	parts = append(parts, "*Fail2Ban:* `fail2ban-client status sshd`")
	parts = append(parts, "vpsguard does not block, kill, quarantine, or lock accounts.")
	parts = append(parts, footer(e))
	return join(parts)
}

func formatMiner(e *event.Event) string {
	parts := headerLines(e, "🚨 *Possible crypto miner detected*")
	if exe := fieldCode(e, "exe"); exe != "" {
		parts = append(parts, "*Process:* `"+exe+"`")
	}
	exe := fieldCode(e, "exe")
	if cmd := fieldCode(e, "cmdline"); cmd != "" && cmd != exe {
		parts = append(parts, "*Cmdline:* `"+cmd+"`")
	}
	if pid := fieldStr(e, "pid"); pid != "" {
		parts = append(parts, "*PID:* "+pid)
	}
	parts = append(parts, "*Reason:* "+esc(e.Message))
	parts = append(parts, footer(e))
	return join(parts)
}

func formatSuspiciousProcess(e *event.Event) string {
	parts := headerLines(e, "🚨 *Suspicious process detected*")
	if exe := fieldCode(e, "exe"); exe != "" {
		parts = append(parts, "*Process:* `"+exe+"`")
	}
	if pid := fieldStr(e, "pid"); pid != "" {
		parts = append(parts, "*PID:* "+pid)
	}
	if reason := fieldStr(e, "reason"); reason != "" {
		parts = append(parts, "*Reason:* "+reason)
	}
	if e.Message != "" {
		parts = append(parts, "*Detail:* "+esc(e.Message))
	}
	parts = append(parts, footer(e))
	return join(parts)
}

func formatReinfection(e *event.Event) string {
	parts := headerLines(e, "🚨 *Reinfection loop detected*")
	if exe := fieldCode(e, "exe"); exe != "" {
		parts = append(parts, "*Exe:* `"+exe+"`")
	}
	if count := fieldStr(e, "count"); count != "" {
		parts = append(parts, "*Seen:* "+count+" times")
	}
	if window := fieldStr(e, "window"); window != "" {
		parts = append(parts, "*Window:* "+window)
	}
	if mute := fieldStr(e, "mute"); mute != "" {
		parts = append(parts, "*Suppressing further alerts for:* "+mute)
	}
	if e.Message != "" {
		parts = append(parts, "*Detail:* "+esc(e.Message))
	}
	if rec := fieldStr(e, "recommended"); rec != "" {
		parts = append(parts, "*Recommended:* "+rec)
	}
	parts = append(parts, footer(e))
	return join(parts)
}

func formatHighCPUProcess(e *event.Event) string {
	parts := headerLines(e, "🚨 *Process using high CPU*")
	if exe := fieldCode(e, "exe"); exe != "" {
		parts = append(parts, "*Process:* `"+exe+"`")
	}
	if pid := fieldStr(e, "pid"); pid != "" {
		parts = append(parts, "*PID:* "+pid)
	}
	if usage := fieldStr(e, "usage_pct"); usage != "" {
		parts = append(parts, "*Usage:* "+usage+"%")
	}
	if s := fieldStr(e, "sustained_seconds"); s != "" {
		parts = append(parts, "*Sustained:* "+s+" seconds")
	}
	if e.Message != "" {
		parts = append(parts, "*Detail:* "+esc(e.Message))
	}
	parts = append(parts, footer(e))
	return join(parts)
}

func formatCPUSpike(e *event.Event) string {
	parts := headerLines(e, "🚨 *Sustained CPU spike*")
	if u := fieldStr(e, "usage_pct"); u != "" {
		parts = append(parts, "*Usage:* "+u+"%")
	}
	if s := fieldStr(e, "sustained_seconds"); s != "" {
		parts = append(parts, "*Sustained:* "+s+" seconds")
	}
	parts = append(parts, "*Detail:* "+esc(e.Message))
	parts = append(parts, footer(e))
	return join(parts)
}

func formatOutbound(e *event.Event, title, advice string) string {
	parts := headerLines(e, title)
	if dsts := fieldStr(e, "unique_dst_ips"); dsts != "" {
		parts = append(parts, "*Remote IPs:* "+dsts)
	}
	if ip := fieldStr(e, "ip"); ip != "" {
		parts = append(parts, "*IP:* "+ip)
	}
	if domain := fieldStr(e, "domain"); domain != "" {
		parts = append(parts, "*Domain:* "+domain)
	}
	if service := fieldStr(e, "service"); service != "" {
		parts = append(parts, "*Service:* "+service)
	}
	if base := fieldStr(e, "base_domain"); base != "" {
		parts = append(parts, "*Base domain:* "+base)
	}
	if port := fieldStr(e, "port"); port != "" {
		parts = append(parts, "*Port:* "+port)
	}
	if ports := fieldStr(e, "ports"); ports != "" {
		parts = append(parts, "*Ports:* "+ports)
	}
	if window := fieldStr(e, "window"); window != "" {
		parts = append(parts, "*Window:* "+window)
	}
	parts = append(parts, advice)
	parts = append(parts, footer(e))
	return join(parts)
}

func formatFileChange(e *event.Event, title, advice string) string {
	parts := headerLines(e, title)
	if path := fieldCode(e, "path"); path != "" {
		parts = append(parts, "*Path:* `"+path+"`")
	}
	if op := fieldStr(e, "op"); op != "" {
		parts = append(parts, "*Op:* "+op)
	}
	if advice != "" {
		parts = append(parts, advice)
	}
	parts = append(parts, footer(e))
	return join(parts)
}

func formatAgent(e *event.Event, title, advice string) string {
	parts := headerLines(e, title)
	if advice != "" {
		parts = append(parts, advice)
	}
	parts = append(parts, footer(e))
	return join(parts)
}

func formatAgentError(e *event.Event) string {
	parts := headerLines(e, "⚠️ *vpsguard detector error*")
	if d := fieldStr(e, "detector"); d != "" {
		parts = append(parts, "*Detector:* "+d)
	}
	if e.Message != "" {
		parts = append(parts, "*Error:* "+esc(e.Message))
	}
	parts = append(parts, footer(e))
	return join(parts)
}

func formatTamper(e *event.Event) string {
	parts := headerLines(e, "🚨 *vpsguard binary changed*")
	if path := fieldCode(e, "path"); path != "" {
		parts = append(parts, "*Path:* `"+path+"`")
	}
	parts = append(parts, "The agent binary changed after startup. If you did not upgrade vpsguard, investigate immediately.")
	parts = append(parts, footer(e))
	return join(parts)
}

func formatGeneric(e *event.Event) string {
	parts := headerLines(e, fmt.Sprintf("%s *%s*", emojiFor(e.Severity), esc(e.Title)))
	if e.Message != "" {
		parts = append(parts, esc(e.Message))
	}
	for k, v := range e.Fields {
		parts = append(parts, "*"+esc(k)+":* "+esc(fmt.Sprintf("%v", v)))
	}
	parts = append(parts, footer(e))
	return join(parts)
}

var _ = time.Now // keep time import; UTC formatting may evolve
