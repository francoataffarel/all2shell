# wp2shell — exposure, mitigation & verification pack

Blue-team pack for the WordPress Core REST batch pre-authentication RCE
(**CVE-2026-63030**, **CVE-2026-60137**), publicly known as **wp2shell**.

> **Scope.** This pack is defensive. It helps you answer two questions —
> *"am I exposed?"* and *"did my fix work?"* — and nothing else. It ships no
> exploit payload and no exploitation steps. Run every check only against hosts
> you own or are explicitly authorized to assess.

## The bug, in one paragraph

A route-confusion flaw in WordPress Core's REST batch handling lets an
unauthenticated request reach a pre-auth SQL injection primitive. Public tooling
chains that into administrator creation and plugin-upload code execution on a
stock install — no plugins required. Full pre-auth RCE affects **6.9.0–6.9.4**
and **7.0.0–7.0.1**; the 6.8 branch (**6.8.0–6.8.5**) is reachable for SQL
injection only. Fixed in **6.8.6**, **6.9.5** and **7.0.2**.

## 1. Detect exposure (non-intrusive)

Two interchangeable options, both read-only:

```bash
# all2shell module — version + batch-route reachability, no payloads
all2shell run wpexposure --target https://your-wordpress-site --yes-authorized

# or a Nuclei template (same idea, fleet-friendly)
nuclei -validate -t detect.nuclei.yaml
nuclei -t detect.nuclei.yaml -u https://your-wordpress-site
```

Both fingerprint the WordPress version and check whether the anonymous REST index
advertises `/batch/v1`. Neither sends a batch request or an SQLi probe. A reported
version can hide a backported fix, so treat "exposed" as *investigate*, not *proof*.

## 2. Remediate

1. **Update** — the only complete fix. Move to **7.0.2** (or **6.9.5** on the 6.9
   branch). Nothing below replaces this.
2. **Block at the edge** — until you can update, have the WAF reject unauthenticated
   `/wp-json/batch/v1` **and** `?rest_route=/batch/v1`. Both patterns are required.
3. **mu-plugin** — drop [`mitigation/disable-unauth-batch-api.php`](mitigation/disable-unauth-batch-api.php)
   into `wp-content/mu-plugins/`. It requires an authenticated user for the batch
   route and loads with no manual activation. Emergency control only; it breaks
   anonymous batch consumers. Remove it after updating.

## 3. Verify the fix

```bash
all2shell run wpexposure --target https://your-wordpress-site --yes-authorized
```

A remediated host returns a **fixed version**, or the batch route now answers
anonymous callers with **HTTP 401**. Also confirm no unexpected administrator
accounts were created during the exposure window.

## 4. Hunt (if you may have been hit)

The randomised `wp2shell_<hex>` plugin slug is a fragile IOC — the durable signal
is a **web-server process spawning a shell** from a plugin directory.

- **Behaviour (durable):** `apache2` / `nginx` / `php-fpm` / `lsphp` spawning
  `sh -c id; whoami; hostname` with `process.working_directory` under
  `wp-content/plugins/`.
- **On disk:** new `.php` under `wp-content/plugins/` or `wp-content/cache/`;
  `temp-write-test-*` probe files under `wp-content/`.
- **Network / access logs:** `POST` to `/wp-json/batch/v1` or `/?rest_route=/batch/v1`
  with a nested `requests` array; `HTTP 207` on batch traffic; `User-Agent: wp2shell`.

See `advisory.yaml` for the structured IOC/MITRE mapping and the Elastic
Security Labs rule names that cover this chain.

## Files

| File | Purpose |
|------|---------|
| `advisory.yaml` | Machine-readable manifest: versions, mitigations, IOCs, references |
| `detect.nuclei.yaml` | Non-intrusive Nuclei exposure template |
| `mitigation/disable-unauth-batch-api.php` | Emergency mu-plugin: require auth for the batch route |
| `README.md` | This runbook |
