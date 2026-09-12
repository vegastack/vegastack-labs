# Phase 3 browser evidence

`pnpm check:phase-3` is the credential-free Phase 3 acceptance command. On Linux it runs Chromium against the embedded Console through the real loopback TLS Go server, synthetic Access JWT/JWKS identity, revocable local session, protected read API, and local Unix-socket recovery path. On other development systems it checks the fixture and sanitation contract; the accepted runtime evidence must come from the approved Debian lane.

The supported Phase 3 browser lane is the repository-pinned Chromium version with desktop and mobile emulation. Firefox, WebKit, additional operating systems, and packaged distributions remain Phase 11 work. The fixture contacts only loopback listeners and does not need Cloudflare, Workspace, provider credentials, public ingress, or fleet access.

## Sanitized evidence policy

The normal result is only `{ "schemaVersion": 1, "check": "phase-3", "status": "pass" }`. Raw traces, screenshots, request logs, cookies, authorization headers, JWTs, claims, private source records, absolute machine paths, and non-loopback endpoints are not retained. A failure may retain only allowlisted JSON or text after `verify-phase-3.mjs` accepts it. Unknown file types, links, oversized files, private canaries, credential words, token shapes, machine paths, and external URLs fail closed. The initial v1 lane uploads no failure artifact, which is safer than uploading an unsanitized trace.

## Manual keyboard and browser-version check

Automation cannot prove that the visual focus indicator is comfortable for every person. Repeat this check against the same built commit used by the Debian acceptance run:

1. Record the exact `node --version`, `pnpm --version`, pinned Playwright version, Chromium version, tested commit, and the time in IST. Do not record a hostname, user path, cookie, token, or private URL.
2. Open the loopback fixture in Chromium at 100% zoom. Use only `Tab`, `Shift+Tab`, `Enter`, `Space`, browser Back, and browser Forward. Confirm focus is always visible, follows reading order, reaches the navigation and theme control, and returns to a sensible control after navigation.
3. Repeat at 200% zoom and the mobile viewport. Confirm there is no two-dimensional page scrolling, clipped status text, hidden focused control, or pointer-only action.
4. Test light, dark, system theme, and reduced motion. Confirm status changes remain named in text and are announced without relying only on color or animation.
5. Deep-link to each read route, refresh it, move back and forward, then exercise logout and expired access. Confirm denied, unknown, stale, unavailable, partial, and error states never appear healthy.
6. Record only pass/fail for each step and stable scenario names. A failure blocks Phase 3; retries do not convert it into a pass.
