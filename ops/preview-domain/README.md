# Parser Studio — no-login HTTPS domain

## Scope

Serve Parser Studio at **https://app.parser.isoc.ooo/** on dev-atlas **without any login page, preview account, or
HTTP Basic authentication**. The owner specifically requires a no-login tool. This is the only public address of
Parser Studio and `isoc-labs/parser-studio` is its only repository. The Exporter sites on the same Nginx
(`exporter.isoc.ooo`, `exporter.xdr.ooo`) belong to another product: preserve them and their configuration.

Until 2026-11-25 the same files were also served as `app.parser.xdr.ooo`, with a second engine process. That host name was retired; Parser Studio is no longer served there (`UPDATE_RUNBOOK.md`, section 7).

## Bounded site topology

| Component | Address | Purpose |
| --- | --- | --- |
| Nginx | `app.parser.isoc.ooo:80,443` | HTTP 301 to HTTPS, no login, separate virtual host |
| Web UI | `/var/www/parser-studio-app` | Pinned production Vite build, not the development server |
| Offline authoring API | `127.0.0.1:4305` | `parser-studio-preview-authoring.service`, only the offline parser-pairs API |
| Multi-Pass source engine | `127.0.0.1:4304` | `parser-studio-preview-multipass.service`, source analysis, no native DP/sensor access |

Both services bind to loopback; Nginx allows only `/api/v1/parser-pairs/` plus the two bounded
`/api/v1/multipass/preview*` routes. Unmatched `/api/` paths return 404. Nginx rejects unwanted POST `Origin`
values, and the engine itself trusts exactly one origin (`PARSER_STUDIO_TRUSTED_ORIGIN` in its unit); neither
introduces any user authentication. HTTPS, payload limits and service isolation remain enabled.

The TLS certificate is the shared ISOC application certificate `/etc/letsencrypt/live/isoc-app-services/`, which
names `app.parser.isoc.ooo`. It is issued and renewed outside this repository; the installer only checks that it
exists and names the host, and never requests a certificate.

This is a public, no-login, stateless authoring endpoint. Do not paste confidential customer log content without
authorization. No automatic LLM transfer, application-initiated sensor forwarding, or DP upload/readback is provided.

## Files in this directory

| File | Purpose |
| --- | --- |
| `nginx-app.parser.isoc.ooo.conf` | the Nginx site |
| `parser-studio-preview-authoring.service`, `parser-studio-preview-multipass.service` | the two systemd units |
| `prepare-private-preview.sh`, `check-staged-files.sh`, `install-private-preview.sh` | first installation of site, units and files |
| `release.sh` | every later update: build, apply, verify, rollback, status (`UPDATE_RUNBOOK.md`) |
| `live_engine_check.py` | shows that the running engine answers as the engine code of a checkout does |
| `playwright.deployed.config.ts` | the browser journeys run against the deployed site by `release.sh verify` |

## Nonprivileged verification

```bash
bash -n ops/preview-domain/install-private-preview.sh
bash -n ops/preview-domain/prepare-private-preview.sh
bash -n ops/preview-domain/release.sh
python3 tests/test_preview_nginx_routing_20261019.py -v
python3 tests/test_preview_domain_wait_20261019.py -v
python3 tests/test_preview_staging_20261019.py -v
python3 tests/test_preview_startup_wait_20261019.py -v
python3 tests/test_preview_single_service_contract_20261125.py -v
python3 tests/test_live_engine_check_20261125.py -v
```

The Nginx test creates an isolated unprivileged HTTPS server with a **temporary test-only certificate**. It checks
unauthenticated UI/API HTTP 200, no WWW-Authenticate header, 301 redirect, blocked routes, and rejected cross-origin
POST. It does **not** prove external-domain deployment. Run these as an ordinary user, never as root.

## First installation on dev-atlas

The package is built from a clean exact Git HEAD with `bash ops/preview-domain/prepare-private-preview.sh`; the
ignored `dist/private-preview` package contains exact-HEAD frontend/backend/source-engine files and SHA-256 hashes.
Never reuse a package from another HEAD. An administrator then runs, from an authorized dev-atlas shell:

```bash
sudo bash ops/preview-domain/install-private-preview.sh "$(git rev-parse HEAD)"
```

The installer does **not** request, create or store a Parser Studio username or password. It runs
`check-staged-files.sh` before touching services (existing destination trees must equal the package), creates the
dedicated Nginx site, installs the two loopback services, waits for bounded health probes instead of failing on the
first cold-start request, validates `nginx -t`, then reloads Nginx. After the reload it retries the exact host name
through the local Nginx listener until HTTP 301 and CA-verified HTTPS 200 with the Parser Studio page title are
served; it never disables TLS validation. The Exporter virtual hosts are not edited. On installation errors, Nginx
routing is restored and the new systemd services are disabled.

## Real-domain acceptance (not automatically satisfied by the installer)

1. Unauthenticated `http://app.parser.isoc.ooo/` redirects 301 to HTTPS.
2. Unauthenticated `https://app.parser.isoc.ooo/` returns HTTP **200**, shows the **Parser Studio** UI, and never
   prompts for a preview login. CSS/JS load successfully.
3. The `/api/v1/parser-pairs/capabilities` endpoint works without authentication; analysis and parser creation work
   after real user clicks.
4. A cross-origin browser POST is rejected (403); unused target/sensor/Test Lab routes are absent (404).
5. The responses of the Exporter sites remain unchanged.
6. `release.sh <sha> verify` passes: Chromium on the real domain, then the generated parsers on Ruby 2.4.9.

A passing local Nginx fixture is not a successful public HTTPS deployment, and a successful structural parser result
is not proof of native Stellar target compatibility.

## Removing the site

Disable **only** the `app.parser.isoc.ooo` site, stop the two `parser-studio-preview-*.service` units, run
`nginx -t`, reload, and verify that the Exporter sites remain available. Do not disable TLS, loosen source-size
bounds, or bypass operating-system privileges.

## Updating the running preview

Application updates (web, authoring backend, Multi-Pass) follow `UPDATE_RUNBOOK.md` and go through `release.sh`:
one contract for the whole service set, with rollback.
