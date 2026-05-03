package dns

// BuiltinBadDomains is a curated list of file-drop, paste, and tunnel
// services that show up overwhelmingly often in stealer / RAT C2 chains
// reported in 2024–2026 threat-intel (Sysdig, Wiz, CADO, Trend Micro,
// Microsoft, Mandiant). Shipping these as defaults lets a freshly-
// installed agent catch the most common exfil patterns without the
// user having to research and populate known_bad_domains themselves.
//
// The user can extend this list (config: known_bad_domains) but the
// builtin list is always in effect — false positives are tolerable
// because vpsguard alerts; it does not block.
var BuiltinBadDomains = []string{
	// Anonymous file-drop services (top stealer exfil paths)
	"transfer.sh",
	"anonfiles.com",
	"file.io",
	"gofile.io",
	"0x0.st",
	"catbox.moe",
	"litterbox.catbox.moe",
	"oshi.at",
	"send.cm",
	"anonymfile.com",
	"qaz.im",
	"upload.ee",
	"workupload.com",

	// Paste services routinely used for in-memory C2 payload delivery
	"paste.ee",
	"hastebin.com",
	"hasteb.in",
	"dpaste.com",
	"dpaste.org",
	"ghostbin.com",
	"controlc.com",
	"sprunge.us",
	"termbin.com",
	"ix.io",
	"rentry.co",
	"justpaste.it",
	"pastes.io",
	"snipboard.io",
	"privatebin.net",

	// IP echo / OS detection services almost never legitimate on a
	// production VPS — usually used by attacker tooling for
	// fingerprinting after compromise.
	"ifconfig.me",
	"ifconfig.io",
	"ipinfo.io",
	"icanhazip.com",
	"checkip.amazonaws.com",
	"api.ipify.org",
	"ipv4.icanhazip.com",
	"my-ip.io",

	// Reverse-tunnel services attackers use to bypass NAT/firewall
	// (they all establish outbound and tunnel inbound). Legitimate
	// in dev workflows but very rarely on a production VPS.
	"ngrok.io",
	"ngrok-free.app",
	"ngrok.app",
	"loca.lt",
	"localtunnel.me",
	"serveo.net",
	"trycloudflare.com",
	"pinggy.online",
	"pinggy.io",
	"tunnel.pyjam.as",

	// Container/registry abuse: scraped public Docker Hub miner images
	// often pull from these. We deliberately do NOT list docker.io
	// itself — too broad. We list known-malicious staging hosts.
	"oast.fun",  // Interactsh OAST canary — also abused in RCE chains
	"oast.live",
	"oast.online",
	"oast.pro",
	"oast.me",
	"oast.site",
	"oast.us",
	"interact.sh",

	// Common stealer C2 patterns — clipboard/keylogger/Discord webhook
	// abuse routes to these. Discord is dual-use; we flag the API
	// path rather than the whole domain to avoid breaking legit users.
	// (Implemented in the matcher: discord.com/api/webhooks)
	"discordapp.com", // legacy webhook host
	"cdn.discordapp.com",
}
