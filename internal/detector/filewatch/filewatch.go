// Package filewatch watches sensitive Linux paths via inotify and emits
// events when they change. Top persistence vectors per the PRD.
package filewatch

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/ceorkm/vpsguard/internal/event"
	"github.com/fsnotify/fsnotify"
)

const Name = "filewatch"

// watch describes a path to monitor and how to classify changes there.
type watch struct {
	path     string
	typ      string
	severity event.Severity
	title    string
	message  string
}

// Default watch list. PRD section 10.6–10.9.
var defaults = []watch{
	// Cron
	{path: "/etc/crontab", typ: event.TypeCronModified, severity: event.SevHigh, title: "Cron file modified", message: "/etc/crontab was modified — common attacker persistence vector"},
	{path: "/etc/cron.d", typ: event.TypeCronModified, severity: event.SevHigh, title: "Cron drop-in directory changed", message: "a file under /etc/cron.d was added or modified"},
	{path: "/etc/cron.hourly", typ: event.TypeCronModified, severity: event.SevHigh, title: "Hourly cron changed"},
	{path: "/etc/cron.daily", typ: event.TypeCronModified, severity: event.SevHigh, title: "Daily cron changed"},
	{path: "/etc/cron.weekly", typ: event.TypeCronModified, severity: event.SevMedium, title: "Weekly cron changed"},
	{path: "/etc/cron.monthly", typ: event.TypeCronModified, severity: event.SevMedium, title: "Monthly cron changed"},
	{path: "/var/spool/cron", typ: event.TypeCronModified, severity: event.SevHigh, title: "User crontab changed"},
	{path: "/var/spool/cron/crontabs", typ: event.TypeCronModified, severity: event.SevHigh, title: "User crontab changed"},

	// Sudoers
	{path: "/etc/sudoers", typ: event.TypeSudoerModified, severity: event.SevCritical, title: "Sudoers file modified", message: "/etc/sudoers was changed — privilege grants may have been altered"},
	{path: "/etc/sudoers.d", typ: event.TypeSudoerModified, severity: event.SevCritical, title: "Sudoers drop-in changed"},

	// Identity
	{path: "/etc/passwd", typ: event.TypeUserCreated, severity: event.SevHigh, title: "/etc/passwd modified", message: "user accounts may have been added or removed"},
	{path: "/etc/shadow", typ: event.TypeUserCreated, severity: event.SevHigh, title: "/etc/shadow modified"},
	{path: "/etc/group", typ: event.TypeUserCreated, severity: event.SevMedium, title: "/etc/group modified"},

	// SSH keys (root)
	{path: "/root/.ssh/authorized_keys", typ: event.TypeSSHKeyAdded, severity: event.SevCritical, title: "Root authorized_keys modified", message: "a new SSH key may grant attacker persistent access"},
	{path: "/root/.ssh", typ: event.TypeSSHKeyAdded, severity: event.SevHigh, title: "Root .ssh directory changed"},

	// Systemd
	{path: "/etc/systemd/system", typ: event.TypeSystemdServiceAdded, severity: event.SevHigh, title: "Systemd unit changed", message: "an attacker-installed service is a common persistence mechanism"},

	// Linker / shell init (high-impact persistence)
	{path: "/etc/ld.so.preload", typ: event.TypeSystemdServiceAdded, severity: event.SevCritical, title: "/etc/ld.so.preload modified", message: "ld.so.preload is a classic linker-rootkit persistence path"},
	{path: "/etc/pam.d", typ: event.TypeSystemdServiceAdded, severity: event.SevCritical, title: "PAM configuration changed", message: "PAM changes can create stealth login backdoors or credential capture"},
	{path: "/lib/security", typ: event.TypeSystemdServiceAdded, severity: event.SevCritical, title: "PAM module path changed", message: "new or modified PAM modules can create covert authentication backdoors"},
	{path: "/lib64/security", typ: event.TypeSystemdServiceAdded, severity: event.SevCritical, title: "PAM module path changed", message: "new or modified PAM modules can create covert authentication backdoors"},
	{path: "/usr/lib/security", typ: event.TypeSystemdServiceAdded, severity: event.SevCritical, title: "PAM module path changed", message: "new or modified PAM modules can create covert authentication backdoors"},
	{path: "/etc/profile", typ: event.TypeSystemdServiceAdded, severity: event.SevMedium, title: "/etc/profile modified"},
	{path: "/etc/profile.d", typ: event.TypeSystemdServiceAdded, severity: event.SevMedium, title: "/etc/profile.d/ changed", message: "scripts in /etc/profile.d run on every interactive shell"},
	{path: "/etc/bash.bashrc", typ: event.TypeSystemdServiceAdded, severity: event.SevMedium, title: "/etc/bash.bashrc modified"},

	// Additional persistence locations from current threat-intel.
	{path: "/etc/rc.local", typ: event.TypeSystemdServiceAdded, severity: event.SevHigh, title: "/etc/rc.local modified", message: "/etc/rc.local runs as root at boot — classic backdoor location"},
	{path: "/etc/update-motd.d", typ: event.TypeSystemdServiceAdded, severity: event.SevHigh, title: "/etc/update-motd.d/ changed", message: "MOTD scripts run on every interactive login as root"},
	{path: "/etc/NetworkManager/dispatcher.d", typ: event.TypeSystemdServiceAdded, severity: event.SevMedium, title: "NetworkManager dispatcher script changed", message: "dispatcher scripts run on netif up/down as root"},
	{path: "/etc/logrotate.d", typ: event.TypeSystemdServiceAdded, severity: event.SevMedium, title: "logrotate config changed", message: "logrotate scripts run as root daily — recent CVEs allow privesc through compromised configs"},
	{path: "/etc/apt/apt.conf.d", typ: event.TypeSystemdServiceAdded, severity: event.SevHigh, title: "apt hook config changed", message: "apt hooks run as root on every package op — trojaned hooks compromise every install"},
	{path: "/etc/dnf/plugins", typ: event.TypeSystemdServiceAdded, severity: event.SevHigh, title: "dnf plugin changed", message: "dnf plugins run as root on every package op"},
	{path: "/etc/yum/pluginconf.d", typ: event.TypeSystemdServiceAdded, severity: event.SevHigh, title: "yum plugin config changed"},
	{path: "/etc/init.d", typ: event.TypeSystemdServiceAdded, severity: event.SevHigh, title: "SysV init script changed"},
	{path: "/etc/xinetd.d", typ: event.TypeSystemdServiceAdded, severity: event.SevHigh, title: "xinetd service changed"},
	{path: "/lib/systemd/system-generators", typ: event.TypeSystemdServiceAdded, severity: event.SevHigh, title: "systemd generator changed", message: "systemd generators run early at boot as root"},
	{path: "/usr/lib/systemd/system-generators", typ: event.TypeSystemdServiceAdded, severity: event.SevHigh, title: "systemd generator changed"},
}

type Detector struct {
	// Optional override; if nil, defaults is used.
	Watches []watch

	// HomeRoot is the parent dir to scan for per-user authorized_keys.
	// Defaults to /home. Tests can point this at a fixture dir.
	HomeRoot string
}

func (d *Detector) Name() string { return Name }

func (d *Detector) Run(ctx context.Context, out chan<- *event.Event) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer w.Close()

	watches := d.Watches
	if watches == nil {
		watches = defaults
	}
	homeRoot := d.HomeRoot
	if homeRoot == "" {
		homeRoot = "/home"
	}

	index := map[string]watch{}
	for _, wt := range watches {
		index[wt.path] = wt
		if err := w.Add(wt.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			parent := filepath.Dir(wt.path)
			if _, ok := index[parent]; !ok {
				_ = w.Add(parent)
			}
		}
	}

	// Per-user authorized_keys discovery. Add every existing
	// /home/<user>/.ssh/authorized_keys as an explicit watch, then watch
	// /home itself for new user dirs (we add their keys when they appear).
	addUserKeys(w, index, homeRoot)
	if err := w.Add(homeRoot); err != nil && !errors.Is(err, os.ErrNotExist) {
		// best-effort
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-w.Events:
			if !ok {
				return nil
			}
			if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove|fsnotify.Rename|fsnotify.Chmod) == 0 {
				continue
			}

			// Dynamic discovery: a new directory under /home likely means
			// useradd ran. Scan it for an authorized_keys and start
			// watching if found.
			if isHomeChild(ev.Name, homeRoot) && ev.Op&fsnotify.Create != 0 {
				addUserKeys(w, index, homeRoot)
			}

			meta := matchWatch(index, ev.Name)
			if meta.path == "" {
				continue
			}
			emit := event.New(meta.typ, meta.severity, meta.title).
				WithSource(Name).
				WithMessage(meta.message).
				WithField("path", ev.Name).
				WithField("op", ev.Op.String())
			if user := userFromPath(ev.Name, homeRoot); user != "" {
				emit.WithField("user", user)
			}

			// Cron-content scan: if this is a cron file/drop-in, peek
			// at the contents. A `curl ... | bash` line in cron is a
			// near-certain attacker persistence pattern; upgrade to
			// critical and surface the offending snippet.
			if meta.typ == event.TypeCronModified && ev.Op&fsnotify.Remove == 0 {
				if r := scanCronContent(ev.Name); r.Reason != "" {
					emit.Severity = event.SevCritical
					emit.Title = "Cron job contains attacker-style payload"
					emit.WithMessage("a modified cron file contains a one-liner pattern strongly associated with miner / botnet / RAT persistence")
					emit.WithField("reason", r.Reason)
					if r.Snippet != "" {
						emit.WithField("snippet", r.Snippet)
					}
				}
			}

			// Shell-init content scan: per-user .bashrc / .profile /
			// .zshrc are favorite persistence files for Diicot, 8220,
			// TeamTNT etc. Reuse the cron-content scanner — it already
			// matches every pattern those families use.
			if meta.typ == event.TypeSystemdServiceAdded &&
				ev.Op&fsnotify.Remove == 0 &&
				isShellInitFile(ev.Name) {
				if r := scanCronContent(ev.Name); r.Reason != "" {
					emit.Severity = event.SevCritical
					emit.Title = "Shell init file contains attacker-style payload"
					emit.WithMessage("a per-user shell init file contains a one-liner pattern strongly associated with miner / botnet / RAT persistence")
					emit.WithField("reason", r.Reason)
					if r.Snippet != "" {
						emit.WithField("snippet", r.Snippet)
					}
				}
			}

			// authorized_keys content scan: when an SSH key file
			// changes, parse the new lines for forced commands and
			// wildcard-from clauses. The classic "command=curl evil|bash"
			// backdoor is the highest-value catch.
			if meta.typ == event.TypeSSHKeyAdded &&
				ev.Op&fsnotify.Remove == 0 &&
				strings.HasSuffix(ev.Name, "/authorized_keys") {
				if r := scanAuthorizedKeys(ev.Name); r.Reason != "" {
					if r.Reason == "forced_command_payload" {
						emit.Severity = event.SevCritical
						emit.Title = "SSH key with attacker-style forced command"
						emit.WithMessage("a key in authorized_keys uses command=\"...\" with curl/wget/base64/dev_tcp/etc. — backdoor pattern")
					} else if r.Reason == "forced_command" {
						emit.Severity = event.SevHigh
						emit.WithMessage("a key in authorized_keys has a forced command — review whether this is intentional")
					} else if r.Reason == "from_wildcard" {
						emit.Severity = event.SevHigh
						emit.WithMessage("a key in authorized_keys uses from=\"*\" or from=\"0.0.0.0/0\" — overly permissive")
					}
					emit.WithField("reason", r.Reason)
					if r.Fingerprint != "" {
						emit.WithField("fingerprint", r.Fingerprint)
					}
					if r.Comment != "" {
						emit.WithField("key_comment", r.Comment)
					}
					if r.Snippet != "" {
						emit.WithField("options", r.Snippet)
					}
				}
			}

			out <- emit
		case err := <-w.Errors:
			if err != nil && ctx.Err() == nil {
				continue
			}
		}
	}
}

// addUserKeys scans homeRoot for ~/<user>/.ssh/authorized_keys files and
// registers a watch per file (idempotent — fsnotify ignores duplicates).
func addUserKeys(w *fsnotify.Watcher, index map[string]watch, homeRoot string) {
	entries, err := os.ReadDir(homeRoot)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		keyPath := filepath.Join(homeRoot, entry.Name(), ".ssh", "authorized_keys")
		sshDir := filepath.Join(homeRoot, entry.Name(), ".ssh")
		if _, ok := index[keyPath]; ok {
			continue
		}
		index[keyPath] = watch{
			path:     keyPath,
			typ:      event.TypeSSHKeyAdded,
			severity: event.SevHigh,
			title:    "User authorized_keys modified",
			message:  "a new SSH key may grant attacker persistent access to a user account",
		}
		index[sshDir] = watch{
			path:     sshDir,
			typ:      event.TypeSSHKeyAdded,
			severity: event.SevMedium,
			title:    "User .ssh directory changed",
		}
		_ = w.Add(keyPath)
		_ = w.Add(sshDir)

		// Per-user shell-init persistence files. Diicot, 8220, and
		// TeamTNT all routinely append loader one-liners to .bashrc /
		// .profile / .zshrc. Coverage here closes a real gap.
		userHome := filepath.Join(homeRoot, entry.Name())
		for _, rcName := range []string{".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", ".bash_aliases"} {
			rcPath := filepath.Join(userHome, rcName)
			if _, ok := index[rcPath]; ok {
				continue
			}
			index[rcPath] = watch{
				path:     rcPath,
				typ:      event.TypeSystemdServiceAdded, // shares persistence event type
				severity: event.SevHigh,
				title:    "User shell init file modified",
				message:  "per-user shell init files (.bashrc/.profile/.zshrc) are a common attacker persistence path",
			}
			_ = w.Add(rcPath)
		}
	}
}

// isShellInitFile reports whether a path looks like a per-user shell
// init file we want to content-scan.
func isShellInitFile(p string) bool {
	for _, n := range []string{".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", ".bash_aliases"} {
		if strings.HasSuffix(p, "/"+n) {
			return true
		}
	}
	return false
}

func isHomeChild(p, homeRoot string) bool {
	cleaned := filepath.Clean(p)
	parent := filepath.Dir(cleaned)
	return parent == filepath.Clean(homeRoot)
}

// userFromPath extracts "<user>" from /home/<user>/... or /root/... paths.
func userFromPath(p, homeRoot string) string {
	cleaned := filepath.Clean(p)
	rootHome := filepath.Clean(homeRoot)
	if strings.HasPrefix(cleaned, rootHome+string(filepath.Separator)) {
		rest := cleaned[len(rootHome)+1:]
		if i := strings.Index(rest, string(filepath.Separator)); i > 0 {
			return rest[:i]
		}
		return rest
	}
	if strings.HasPrefix(cleaned, "/root") {
		return "root"
	}
	return ""
}

func matchWatch(index map[string]watch, p string) watch {
	if w, ok := index[p]; ok {
		return w
	}
	for path, w := range index {
		if strings.HasPrefix(p, path+"/") {
			return w
		}
	}
	return watch{}
}
