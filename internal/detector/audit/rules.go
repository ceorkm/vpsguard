package audit

const Rules = `# vpsguard auditd rules
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F a2&04000 -k vpsguard-setuid
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k vpsguard-kernel-module
-a always,exit -F arch=b64 -S ptrace -k vpsguard-ptrace
-w /etc/shadow -p r -k vpsguard-sensitive
-w /root/.ssh -p r -k vpsguard-sensitive
-w /etc/pam.d -p wa -k vpsguard-pam
-w /lib/security -p wa -k vpsguard-pam
-w /lib64/security -p wa -k vpsguard-pam
-w /var/run/docker.sock -p rw -k vpsguard-docker-sock
`
