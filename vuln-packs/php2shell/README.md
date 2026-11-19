# PHP2Shell — exposure, mitigation & verification pack

Blue-team pack for **PHP2Shell** — two PHP-core unauthenticated RCE flaws,
**CVE-2026-109618** (out-of-memory corruption) and **CVE-2026-109619** (stale global state /
use-after-free). The bugs are in the PHP runtime, so secure application code does not protect
you; risk is highest on Apache **mod_php**. Fixed **2026-10-21** in **8.5.12 / 8.4.27 /
8.3.36 / 8.2.35**. Exploited in the wild.

> **Scope.** Defensive only: establish exposure, apply the fix/mitigation, verify. No exploit
> request is ever sent.

## 1. Detect exposure (non-intrusive)

```bash
# Host-local: PHP version per branch + whether session.upload_progress is enabled
all2shell run phpexposure --yes-authorized

# Optional remote version fingerprint from headers (coverage limited by expose_php):
all2shell run phpexposure --target https://your-site --yes-authorized

# Fleet fingerprint:
nuclei -validate -t detect.nuclei.yaml
nuclei -t detect.nuclei.yaml -u https://your-site
```

A reported version can hide a backported fix, and a product may ship its own PHP — check the
runtime each *service* uses, not just the CLI build.

## 2. Remediate

1. **Update** — the only complete fix: **8.5.12 / 8.4.27 / 8.3.36 / 8.2.35**, or your distro's
   patched package. Restart FPM/Apache workers afterwards.
2. **Stopgap** — install [`mitigation/99-php2shell.ini`](mitigation/99-php2shell.ini)
   (`session.upload_progress.enabled = Off`) where the **web** SAPI reads it (FPM/Apache
   php.ini or an FPM pool), then restart workers. This is **partial** — it closes the 109619
   path and CVE-2026-115560, not CVE-2026-109618.
3. **End-of-life branch (<8.2)** — no patch is coming; move to a supported branch.

## 3. Verify the fix

```bash
all2shell run phpexposure --yes-authorized
```

Fixed means the version is at or above the branch's fixed release. Confirm with `phpinfo()`
that the edited file is the **Loaded Configuration File** and that workers restarted — the
mitigation is most often applied to the CLI `php.ini` by mistake.

## 4. Hunt (if you may have been hit)

- A PHP worker (`php-fpm` / `lsphp` / `apache2` with mod_php) spawning a shell and running
  discovery commands — the durable signal.
- Review internet-facing PHP access logs from ~**October 17, 2026** onward.

## A note on the third CVE

On 2026-10-23 PHP disclosed **CVE-2026-115560**, a narrow session-upload-progress +
runtime `serialize_handler` path that also affects the fixed releases. It is handled in the
next regular release; the same `session.upload_progress.enabled=0` stopgap applies. Keep the
mitigation ini in place after patching until that release ships.

## Files

| File | Purpose |
|------|---------|
| `advisory.yaml` | Per-branch fixed versions, mitigations, references |
| `detect.nuclei.yaml` | Non-intrusive header version fingerprint |
| `mitigation/99-php2shell.ini` | Partial stopgap: disable session upload progress |
| `README.md` | This runbook |
