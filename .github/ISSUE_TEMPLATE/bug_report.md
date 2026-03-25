---
name: Bug Report
about: Report a bug in systemd-netlogd
title: ''
labels: bug
assignees: ''
---

**systemd-netlogd version**
Output of `systemd-netlogd --version`:

**OS and systemd version**
- Distribution:
- systemd version (`systemctl --version`):

**Configuration**
```ini
# Contents of /etc/systemd/netlogd.conf (redact sensitive data)
[Network]
Address=
Protocol=
```

**Describe the bug**
A clear description of what the bug is.

**Steps to reproduce**
1.
2.
3.

**Expected behavior**
What you expected to happen.

**Actual behavior**
What actually happened.

**Logs**
```
# Output of: journalctl -u systemd-netlogd -n 50
```

**Additional context**
Any other relevant information (network setup, TLS certificates, firewall rules, etc.).
