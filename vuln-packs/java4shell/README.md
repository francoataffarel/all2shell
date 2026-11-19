# Java4Shell — exposure, mitigation & verification pack

Blue-team pack for **Java4Shell** (**CVE-2026-114938**), a memory-corruption flaw in
HotSpot's AVX-512 Base64 decoder. A short malformed Base64 string from an unauthenticated
attacker corrupts JVM memory — easy to crash, hard to turn into RCE.

> **Scope.** Defensive only: establish exposure (runtime build + CPU), point at the fix,
> verify it. No exploit payload, no decoder input is ever sent.
>
> **Do not** download "Java4Shell RCE" PoCs from GitHub — fake PoCs for headline CVEs
> routinely carry malware. Confirm exposure with the host-local check below.

## What has to be true to be exposed

1. **Affected runtime** — OpenJDK 17.0.6–17.0.21.0.3, 21 ≤21.0.13.0.3, 25 ≤25.0.5.0.3,
   27 ≤27.0.1.0.3 (and some vendor builds). Java 8, Java 11 and OpenJDK 17.0.0–17.0.5 do
   **not** contain the code.
2. **Affected hardware** — x86-64 with AVX-512 VBMI: all four CPU flags
   `avx512f avx512bw avx512vbmi bmi2`. ARM64 and older x86 are not affected. This gate is
   the cleanest signal: no flags → not exposed, whatever the JDK.
3. For **RCE** specifically (not just a crash): an exposed decoder reachable pre-auth and a
   per-application exploit. Crashes are easy; RCE has only been shown in controlled labs.

## 1. Detect exposure (host-local, non-intrusive)

```bash
all2shell run javaexposure --yes-authorized
all2shell run javaexposure --format json --yes-authorized
```

It reads `java -version` and `/proc/cpuinfo` — nothing else. Because a product may ship its
own JRE, also check the runtime each *service* actually uses, not just the host default.

## 2. Remediate

1. **Update** — move to the November 17, 2026 OpenJDK/Oracle build or your vendor's patched
   distribution (e.g. 17.0.21.1, 21.0.13.1, 25.0.5.1, 27.0.1.1). Update bundled runtimes and
   rebuild container images on patched bases.
2. **Disable the intrinsic** — `-XX:-UseBASE64Intrinsics` turns off only the vulnerable
   decoder and keeps other AVX-512 optimisations.
3. **Disable AVX-512** — `-XX:UseAVX=2` as an alternative, **x86-64 only** (OpenJDK on ARM
   rejects the flag and won't start).

## 3. Verify the fix

```bash
all2shell run javaexposure --yes-authorized
```

Remediated means a fixed build, **or** the CPU lacks an AVX-512 VBMI flag, **or** the
mitigation flag is live on the JVM command line. Confirm the flag reached the right process.

## 4. Hunt (if you may have been hit)

- Unexpected JVM crashes and `hs_err_pid*.log` files on affected hosts.
- Bursts of `IllegalArgumentException` from `java.util.Base64.Decoder` on inputs ending `=`.
- If seen on an exposed service, treat secrets held in that JVM's memory as compromised and
  rotate signing keys, tokens and credentials.

## Files

| File | Purpose |
|------|---------|
| `advisory.yaml` | Runtime/hardware affected data, mitigations, hunt guidance |
| `README.md` | This runbook |

No Nuclei template ships here: exposure depends on the exact JDK build and the CPU, neither
of which is a safe non-intrusive remote signal. Detection is host-local by design.
