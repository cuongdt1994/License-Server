# PM2 Runtime UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the license server run cleanly under PM2 and refresh the admin UI so common operations are easier to scan and use.

**Architecture:** Keep the existing Express/EJS monolith, but extract runtime configuration into a small module so ports, host, data path, and PM2 status are testable. Keep UI changes in EJS/CSS with no new frontend build step.

**Tech Stack:** Node.js, Express, EJS, PM2 ecosystem config, built-in `assert` tests.

---

### Task 1: Runtime Configuration

**Files:**
- Create: `license_server/runtime_config.js`
- Create: `license_server/test/runtime_config.test.js`
- Modify: `license_server/server.js`
- Modify: `license_server/package.json`

- [ ] Write tests for env-driven `WEB_PORT`, `TCP_PORT`, `LICENSE_BIND_HOST`, PM2 detection, and config warnings.
- [ ] Run `node test/runtime_config.test.js` and verify it fails because the module does not exist.
- [ ] Implement `runtime_config.js` with parsing, defaults, warnings, and PM2 metadata.
- [ ] Wire `server.js` to use runtime config for listen ports/host and `/health`.
- [ ] Add the new test to `npm test`.

### Task 2: PM2 Assets

**Files:**
- Create: `license_server/ecosystem.config.js`
- Create: `license_server/PM2.md`
- Modify: `license_server/package.json`
- Test: `license_server/test/pm2_config.test.js`

- [ ] Write tests that load `ecosystem.config.js` and assert app name, script, env defaults, logs, restart policy, and health-facing env names.
- [ ] Run `node test/pm2_config.test.js` and verify it fails before the config exists.
- [ ] Add PM2 scripts: `pm2:start`, `pm2:restart`, `pm2:stop`, `pm2:logs`, `pm2:save`.
- [ ] Document setup, first-run env secrets, data directory, logs, and restart commands.

### Task 3: UI System

**Files:**
- Modify: `license_server/views/layout.ejs`
- Modify: `license_server/views/dashboard.ejs`
- Modify: `license_server/views/machines.ejs`
- Modify: `license_server/views/settings.ejs`
- Modify: `license_server/views/logs.ejs`
- Test: existing UI text tests plus new targeted assertions if needed.

- [ ] Move shared navigation and polished CSS primitives into `layout.ejs`.
- [ ] Make Dashboard and Machines render inside the shared layout instead of duplicating full HTML shells.
- [ ] Add runtime/PM2 status panels in Settings using values already passed from `server.js`.
- [ ] Keep UI responsive with readable tables, compact metrics, accessible controls, and consistent Vietnamese labels.
- [ ] Preserve existing POST routes and CSRF behavior.

### Task 4: Verification

**Files:**
- All modified files.

- [ ] Run `npm test`.
- [ ] Start the app locally with safe test env values.
- [ ] Hit `/health` and confirm JSON includes web/tcp/runtime fields.
- [ ] Inspect changed files with `git diff --check` and `git diff --stat`.
