# nginx2root — exposure, mitigation & verification pack

Blue-team pack for the **nginx2root** remote code execution cluster: five independent
nginx memory-safety flaws, each reaching unauthenticated RCE as the nginx worker in a
specific configuration — **CVE-2026-123007**, **CVE-2026-123633**, **CVE-2026-123634**,
**CVE-2026-121810**, **CVE-2026-113425**. Fixed in **1.31.9** (mainline) / **1.30.7** (stable).

> **Scope.** Defensive only. This pack checks exposure, points at the right mitigation per
> configuration, and verifies the fix. It ships no exploit frames and no exploitation steps.
> Run every check only on hosts you own or are authorized to assess.

## Which flaw hits which configuration

| CVE | Bug | First affected | Requires | Disabling HTTP/2 blocks it? |
|-----|-----|----------------|----------|------------------------------|
| CVE-2026-123007 | HTTP/2 send_window underflow | 1.9.5 | HTTP/2 enabled | **Yes** |
| CVE-2026-123633 | HTTP/2 connection UAF | 1.19.7 | HTTP/2 + upstream proxy | **Yes** |
| CVE-2026-123634 | resolver UAF | 1.13.4 | resolver + request-derived `proxy_pass` + `mirror` | No |
| CVE-2026-121810 | HTTP/3 (QUIC) UAF | 1.25.0 | HTTP/3 + upstream proxy | No |
| CVE-2026-113425 | mail proxy UAF | 0.5.33 | mail `proxy on` + `auth_http` | No |

All five are fixed in 1.31.9 / 1.30.7. The **October 2026** release (1.31.7 / 1.30.6) fixed a
*different* set of CVEs and does **not** cover nginx2root.

## 1. Detect exposure (non-intrusive)

```bash
# Host-local: version + HTTP/2/HTTP/3 modules + enabled directives, plus an
# optional external ALPN probe. Reads config only; sends no exploit frames.
all2shell run nginxexposure --target your-host.example.com --yes-authorized

# Fleet version fingerprint from the Server banner (coverage limited by server_tokens):
nuclei -validate -t detect.nuclei.yaml
nuclei -t detect.nuclei.yaml -u https://your-host.example.com
```

A reported version can hide a backported fix, so treat "exposed" as *investigate*. Confirm
the full distribution package revision against your vendor's advisory.

## 2. Remediate

1. **Update** — the complete fix: **1.31.9** (mainline) or **1.30.7** (stable), or a vendor
   build that lists all five CVEs. Restart nginx; a reload does not swap the running binary.
2. **Disable HTTP/2** (CVE-2026-123007, CVE-2026-123633) — `http2 off;` on affected server
   blocks (≥1.25.1), or drop the `http2` parameter from `listen` on older builds.
3. **Fixed upstreams** (CVE-2026-123634) — point `proxy_pass` at a fixed upstream group to
   remove request-time DNS. `mirror_request_body on` alone is not a fix.
4. **Disable HTTP/3** (CVE-2026-121810) — remove QUIC listeners, `http3 off;`, advertise
   `Alt-Svc 'clear'`, and block UDP/443 at the firewall.
5. **Restrict the mail proxy** (CVE-2026-113425) — bind IMAP/POP3/SMTP to loopback or
   firewall it to trusted clients.

## 3. Verify the fix

```bash
all2shell run nginxexposure --target your-host.example.com --yes-authorized
```

A remediated host reports a fixed version (or a confirmed backport), or the affected feature
is now off. Confirm old workers exited — a reload leaves open HTTP/2 sessions on old workers.

## 4. Hunt (if you may have been hit)

CVE-2026-123007 barely touches access logs: its `WINDOW_UPDATE` / `RST_STREAM` control frames
are not logged as requests and are TLS-encrypted. Lean on host behaviour:

- **Worker executes a program (strongest signal).** An nginx worker has no reason to run
  `/bin/sh`. Add an auditd rule scoped to the worker UID:
  `auditctl -a always,exit -F arch=b64 -S execve,execveat -F euid=<nginx_worker_uid> -k nginx_worker_exec`
- **Abnormal worker exits.** `grep -Ei 'worker process.*exited|signal 11|segfault' /var/log/nginx/error.log` and `coredumpctl list nginx`.
- **Traffic shape.** One long-lived HTTP/2 connection with `bytes_received` climbing fast while
  logged `request_length` stays small, plus many short TLS connections from the same IP.

See `advisory.yaml` for the structured per-CVE data and hunt commands.

## Files

| File | Purpose |
|------|---------|
| `advisory.yaml` | Per-CVE affected ranges, requirements, mitigations, hunt commands |
| `detect.nuclei.yaml` | Non-intrusive Server-banner version fingerprint (CVE-2026-123007) |
| `README.md` | This runbook |

> **Host root.** The researchers chained an nginx worker foothold to a separate Linux kernel
> SCTP flaw to reach host root (and escaped a container). Patch the kernel and assess SCTP
> exposure separately; it is out of scope for this pack.
