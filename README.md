# NestJS Security Lab — Lessons Learned & Hardening Guide

This document summarises what the **Newsroom API** lab teaches about securing a NestJS
application, explains *why* each control exists, and lists the weaknesses that are still
present in the lab code (both `src/` and the reference `endingState/`) together with
concrete improvements.

> The lab is a teaching project. Several shortcuts are deliberate. Treat the
> "Improvements" sections as the checklist for turning it into something you could deploy.

---

## Table of contents

1. [Big picture: the request pipeline](#1-big-picture-the-request-pipeline)
2. [Step 2 — Authentication with JWT](#2-step-2--authentication-with-jwt)
3. [Step 3 — Protecting routes with guards](#3-step-3--protecting-routes-with-guards)
4. [Step 4 — Storing the JWT in an httpOnly cookie](#4-step-4--storing-the-jwt-in-an-httponly-cookie)
5. [Step 5 — Role-based access control (RBAC)](#5-step-5--role-based-access-control-rbac)
6. [Step 6 — Rate limiting with @nestjs/throttler](#6-step-6--rate-limiting-with-nestjsthrottler)
7. [Step 7 — CSRF protection](#7-step-7--csrf-protection)
8. [Step 8 — CORS](#8-step-8--cors)
9. [Step 9 — Helmet, Content Security Policy and nonces](#9-step-9--helmet-content-security-policy-and-nonces)
10. [Cross-cutting issues found in the codebase](#10-cross-cutting-issues-found-in-the-codebase)
11. [Prioritised improvement backlog](#11-prioritised-improvement-backlog)
12. [General security principles to take away](#12-general-security-principles-to-take-away)

---

## 1. Big picture: the request pipeline

Every security control in NestJS lives at a specific point in the request lifecycle.
Knowing the order tells you *where* a control belongs:

```
Incoming request
  │
  ├─ Express middleware (app.use)      → helmet, cors, cookie-parser, csurf, nonce
  ├─ Nest middleware (NestMiddleware)  → per-route middleware
  ├─ Guards (CanActivate)              → authentication (JwtAuthGuard), authorization (RolesGuard), ThrottlerGuard
  ├─ Interceptors (before)             → logging, serialization setup
  ├─ Pipes                             → ValidationPipe, ParseIntPipe
  ├─ Controller handler
  ├─ Interceptors (after)              → ClassSerializerInterceptor (strip secrets from responses)
  └─ Exception filters                 → map errors to safe HTTP responses
```

Rules of thumb:

- **Middleware** handles transport-level concerns (headers, cookies, CORS, CSRF) that do
  not need to know which handler will run.
- **Guards** answer "may this request reach the handler?". They have access to the
  `ExecutionContext` and therefore to metadata such as `@Roles()`.
- **Pipes** answer "is this input well-formed?".
- **Interceptors / filters** control what leaves the server.

---

## 2. Step 2 — Authentication with JWT

**Files:** [auth.module.ts](src/auth/auth.module.ts), [auth.service.ts](src/auth/auth.service.ts), [jwt-auth.guard.ts](src/auth/jwt-auth.guard.ts)

### What the lab teaches

- Register `JwtModule` asynchronously so the secret and expiry come from configuration,
  never from source code (`configService.getOrThrow('JWT_SECRET')`).
- Passwords are stored as **bcrypt hashes** and compared with `bcrypt.compare` — the
  plain password is never stored or compared directly.
- On successful login the server signs a JWT with `sub` (user id), `username` and `role`.
- A custom `JwtAuthGuard` extracts the token, verifies its signature and expiry, and
  attaches the payload to `request.user`. Any failure → `401 Unauthorized`.

### Why it matters

A JWT is a **bearer credential**: whoever holds it *is* the user until it expires. Its
integrity rests entirely on the secret, so secret handling and expiry are as important as
the verification code.

### Weaknesses & improvements

| # | Issue | Where | Fix |
|---|-------|-------|-----|
| 2.1 | **User enumeration via error message.** `src` returns `"User with such username cannot be found"` vs `"Invalid credentials"`. An attacker can discover valid usernames. | [auth.service.ts:16-20](src/auth/auth.service.ts#L16-L20) | Always return the same generic message (the `endingState` version does this correctly). |
| 2.2 | **User enumeration via timing.** When the user doesn't exist, `bcrypt.compare` is skipped, so the response is measurably faster. | [auth.service.ts](src/auth/auth.service.ts) | Compare against a dummy hash when the user is missing so both paths cost the same. |
| 2.3 | **Scheme not checked.** The guard accepts `Authorization: Anything <token>`. | [jwt-auth.guard.ts:31-36](src/auth/jwt-auth.guard.ts#L31-L36) | Require `type === 'Bearer'`. |
| 2.4 | **Algorithm not pinned.** `verify()` accepts whatever `alg` the library allows by default. | guard / module | Set `verifyOptions: { algorithms: ['HS256'] }` (or move to `RS256`/`EdDSA` with key pairs if other services must verify tokens). |
| 2.5 | **No `iss` / `aud` claims.** A token minted for another service using the same secret would be accepted. | module | Add `issuer` and `audience` to `signOptions` and `verifyOptions`. |
| 2.6 | **Secret read twice, inconsistently.** The guard re-reads `JWT_SECRET` with `get()` (may be `undefined`) instead of relying on the module config. | [jwt-auth.guard.ts:43](src/auth/jwt-auth.guard.ts#L43) | Call `this.jwtService.verifyAsync(token)` with no explicit secret — the module already has it. |
| 2.7 | **No revocation / logout.** A stolen token stays valid until expiry; a demoted admin keeps `role: admin` in their token. | design | Short-lived access tokens (5–15 min) + rotating refresh tokens stored server-side, or a `tokenVersion` column checked on each request. |
| 2.8 | **Manual `iat`.** `jsonwebtoken` already sets `iat`. | [auth.service.ts](src/auth/auth.service.ts) | Remove it to avoid clock mistakes. |
| 2.9 | **Weak secret risk.** `.env.example` only says "replace-with-a-long-random-secret". | [.env.example](.env.example) | Validate config at boot (e.g. Joi / zod schema in `ConfigModule.forRoot({ validationSchema })`) and require ≥ 32 random bytes. |

Example of a hardened login:

```ts
// Pre-computed once: bcrypt.hashSync('dummy-password', 12)
const DUMMY_HASH = '$2a$12$C6UzMDM.H6dfI/f/IKcEeO...';

async login(username: string, password: string) {
  const user = await this.usersService.findByUsername(username);
  const ok = await bcrypt.compare(password, user?.password ?? DUMMY_HASH);
  if (!user || !ok) throw new UnauthorizedException('Invalid credentials');

  return {
    access_token: await this.jwtService.signAsync({ sub: user.id, role: user.role }),
  };
}
```

---

## 3. Step 3 — Protecting routes with guards

**Files:** [articles.controller.ts](src/articles/articles.controller.ts), [users.controller.ts](src/users/users.controller.ts), [auth.controller.ts](src/auth/auth.controller.ts)

### What the lab teaches

- `@UseGuards(JwtAuthGuard)` on a handler or controller rejects unauthenticated calls
  with `401`.
- Modules that use the guard must import `AuthModule` (which exports `JwtModule`);
  `forwardRef()` breaks the `AuthModule ⇄ UsersModule` circular dependency.

### Weakness: "secure by opt-in"

Every new route is **public unless someone remembers** to add `@UseGuards`. This is the
single most common cause of broken access control (OWASP A01).

### Improvement: deny by default

Register the guard globally and explicitly mark the few public routes:

```ts
// public.decorator.ts
export const IS_PUBLIC_KEY = 'isPublic';
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);

// jwt-auth.guard.ts
canActivate(ctx: ExecutionContext) {
  const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
    ctx.getHandler(),
    ctx.getClass(),
  ]);
  if (isPublic) return true;
  // ...verify token
}

// app.module.ts
providers: [
  { provide: APP_GUARD, useClass: ThrottlerGuard },
  { provide: APP_GUARD, useClass: JwtAuthGuard },
  { provide: APP_GUARD, useClass: RolesGuard },
];

// auth.controller.ts
@Public() @Post('login') login() { ... }
```

Global guards run in the order they are registered, so authentication always runs
before authorization.

---

## 4. Step 4 — Storing the JWT in an httpOnly cookie

**Reference:** [endingState/auth.controller.ts](endingState/auth.controller.ts), [endingState/jwt-auth.guard.ts](endingState/jwt-auth.guard.ts)

### What the lab teaches

- `cookie-parser` makes `request.cookies` available.
- On login the token is written to an `access_token` cookie with `httpOnly: true`, so
  JavaScript (and therefore an XSS payload) cannot read it.
- The guard reads the token from the cookie instead of the `Authorization` header.

### Trade-off to understand

| Storage | XSS can steal token? | CSRF possible? |
|---------|---------------------|----------------|
| `localStorage` + `Authorization` header | **Yes** | No (browser never sends it automatically) |
| `httpOnly` cookie | No | **Yes** (browser sends it automatically) → needs Step 7 |

Moving to cookies trades one risk for another; that is why CSRF protection follows.

### Weaknesses & improvements

| # | Issue | Fix |
|---|-------|-----|
| 4.1 | `secure: false` — the cookie is sent over plain HTTP. | `secure: process.env.NODE_ENV === 'production'` (and serve only over HTTPS). |
| 4.2 | No `sameSite` on the auth cookie. | `sameSite: 'strict'` (or `'lax'` if you need top-level navigations from other sites). This alone blocks most CSRF. |
| 4.3 | The login response **also returns the token in the body** (`.send(accessToken)`), which defeats `httpOnly` — frontend code will likely store it. | Return `{ success: true }` or the user profile only. |
| 4.4 | `maxAge` is hard-coded to 1 h, independent of `JWT_EXPIRATION`. | Derive both from the same config value. |
| 4.5 | No logout endpoint. | `POST /auth/logout` → `res.clearCookie('access_token', sameOptions)` (+ revoke refresh token). |
| 4.6 | Using `@Res()` switches Nest to "library-specific mode" and bypasses interceptors. | Use `@Res({ passthrough: true })` and `return` the body. |
| 4.7 | Consider the `__Host-` cookie prefix. | `__Host-access_token` forces `Secure`, `Path=/`, no `Domain` — prevents subdomain cookie injection. |

---

## 5. Step 5 — Role-based access control (RBAC)

**Reference:** [endingState/roles.decorator.ts](endingState/roles.decorator.ts), [endingState/roles.guard.ts](endingState/roles.guard.ts)

### What the lab teaches

- `SetMetadata(ROLES_KEY, roles)` wrapped in a `@Roles(...)` decorator attaches the
  required roles to a handler.
- `RolesGuard` uses `Reflector` to read that metadata and compares it with
  `request.user.role`. Mismatch → `403 Forbidden`.
- **Authentication (401) ≠ Authorization (403).** `JwtAuthGuard` must run first so that
  `request.user` exists: `@UseGuards(JwtAuthGuard, RolesGuard)`.

Resulting access matrix:

| Endpoint | Allowed roles |
|----------|---------------|
| `POST /articles` | admin, editor |
| `GET /articles` | any authenticated user |
| `DELETE /articles/:id` | admin |
| `GET /users` | admin |
| `POST /users/register` | public |

### Weaknesses & improvements

| # | Issue | Severity | Fix |
|---|-------|----------|-----|
| 5.1 | **Privilege escalation at registration.** `RegisterUserDto` lets the caller choose `role: 'admin'`. Anyone can register as admin, making all RBAC meaningless. | **Critical** | Remove `role` from the public DTO; always create `UserRole.USER`. Provide a separate admin-only endpoint to change roles. |
| 5.2 | `reflector.get(ROLES_KEY, context.getHandler())` ignores `@Roles()` placed on the **controller class**. | Medium | Use `reflector.getAllAndOverride(ROLES_KEY, [ctx.getHandler(), ctx.getClass()])`. |
| 5.3 | Role is trusted from the JWT, so role changes only take effect after the token expires. | Medium | Short token TTL, or load the user's current role from DB/cache in the guard. |
| 5.4 | No object-level authorization (e.g. "editors may delete **their own** articles"). RBAC alone can't express ownership; missing ownership checks are IDOR bugs. | Design | Check `article.user.id === req.user.sub` in the service, or adopt CASL / policy-based authorization. |
| 5.5 | `:id` is converted with `Number(id)` — `"abc"` becomes `NaN`. | Low | `@Param('id', ParseIntPipe) id: number`. |

---

## 6. Step 6 — Rate limiting with @nestjs/throttler

**Reference:** [endingState/app.module.ts](endingState/app.module.ts), [endingState/articles.controller.ts](endingState/articles.controller.ts)

### What the lab teaches

- `ThrottlerModule.forRoot({ throttlers: [{ ttl: 20_000, limit: 5 }] })` defines a default
  limit (TTL is in **milliseconds** in v5+).
- `@UseGuards(ThrottlerGuard)` applies it; `@Throttle({ default: { limit, ttl } })`
  overrides per route; `@SkipThrottle()` disables it.
- Exceeding the limit returns `429 Too Many Requests`.

### Why it matters

Rate limiting mitigates brute-force login, credential stuffing, scraping and cheap
application-level DoS.

### Weaknesses & improvements

| # | Issue | Fix |
|---|-------|-----|
| 6.1 | **`POST /auth/login` and `POST /users/register` are not throttled** — the endpoints that need it most. | Register `ThrottlerGuard` as `APP_GUARD` and put a strict limit on login (e.g. 5/min per IP + per username). |
| 6.2 | `DELETE /articles/:id` uses `@SkipThrottle()`. Skipping limits on a destructive endpoint is the opposite of what you want. | Remove `@SkipThrottle()` there; reserve it for health checks. |
| 6.3 | Default storage is in-memory — each instance counts separately and counters reset on restart. | Use a shared store (`@nest-lab/throttler-storage-redis`). |
| 6.4 | Behind a reverse proxy every request appears to come from the proxy IP. | `app.set('trust proxy', 1)` (exact hop count) and/or override `getTracker()` to use user id for authenticated routes. |
| 6.5 | Throttling is per-IP only; attackers rotate IPs. | Add per-account lockout/backoff and alerting on failed logins. |

---

## 7. Step 7 — CSRF protection

**Files:** [csrf.controller.ts](src/csrf/csrf.controller.ts), [csurf.guard.ts](src/csrf/csurf.guard.ts), [endingState/main.ts](endingState/main.ts)

### What the lab teaches

- Once auth lives in a cookie, a malicious site can make the victim's browser send
  authenticated state-changing requests (Cross-Site Request Forgery).
- The **synchronizer token** pattern: the server issues a token (`GET /csrf-token`) and
  every `POST/PUT/DELETE` must echo it back in the `X-CSRF-Token` header. A cross-site
  attacker can send the cookie but cannot read the token.
- Safe methods (`GET`, `HEAD`, `OPTIONS`) are ignored — which is only correct if `GET`
  handlers never change state.

### Weaknesses & improvements

| # | Issue | Fix |
|---|-------|-----|
| 7.1 | **`csurf` is deprecated and unmaintained** (archived by the Express team in 2022). | Migrate to `csrf-csrf` (signed double-submit cookie) or `@fastify/csrf-protection`. |
| 7.2 | Two implementations exist: global `app.use(csurf(...))` and a `CsrfGuard` with its own `csurf({ cookie: true })` instance with weaker cookie options. | Keep one mechanism. |
| 7.3 | `secure: false` on the CSRF secret cookie. | `secure: true` in production. |
| 7.4 | `console.error` logs full CSRF errors. | Use Nest `Logger`, log at `warn` without request bodies. |
| 7.5 | CSRF tokens are defence-in-depth, not the only line. | Combine with `SameSite=strict/lax` auth cookies and an `Origin`/`Sec-Fetch-Site` header check on unsafe methods. |

---

## 8. Step 8 — CORS

**Reference:** [endingState/main.ts](endingState/main.ts)

### What the lab teaches

- `app.enableCors()` with no options allows **any origin** — fine for a public read-only
  API, dangerous for a cookie-authenticated one.
- A strict config lists allowed `origin`s, `methods`, `allowedHeaders`, and sets
  `credentials: true` so cookies are sent cross-origin.

### Key understanding

- CORS is **not** an access-control mechanism for your API; it only tells *browsers*
  which origins may *read* responses. `curl` ignores it entirely.
- `credentials: true` **must never** be combined with `origin: '*'` or with reflecting the
  request `Origin` back unconditionally.

### Improvements

- Load the allow-list from configuration (`CORS_ORIGINS=https://app.example.com`) instead
  of hard-coding it.
- Add `PUT`/`PATCH` only if the API actually uses them — keep the list minimal.
- Set `maxAge` for preflight caching.

---

## 9. Step 9 — Helmet, Content Security Policy and nonces

**Files:** [nonce.middleware.ts](src/nonce.middleware.ts), [csp-violations.controller.ts](src/csp-violations/csp-violations.controller.ts), [endingState/main.ts](endingState/main.ts)

### What the lab teaches

- `helmet()` sets a bundle of protective headers: `Content-Security-Policy`,
  `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy`, `Cross-Origin-*-Policy`, and removes
  `X-Powered-By`.
- **CSP** restricts where scripts, styles and fonts may load from. The
  `/csp-violations` page demonstrates what is blocked: inline scripts, unknown external
  scripts, inline `onclick` handlers, inline styles, and framing (clickjacking).
- Three ways to allow a specific resource:
  - **Host allow-list** — `https://nest-js-security-good.com`
  - **Nonce** — a fresh random value per response (`randomBytes(16)`) placed in both the
    CSP header and `<script nonce="...">`.
  - **Hash** — `'sha256-…'` of an exact inline block (used for the inline style).

### Improvements

| # | Issue | Fix |
|---|-------|-----|
| 9.1 | No CSP violation reporting. | Add `report-to` / `report-uri` directive and an endpoint that logs reports. Roll out new policies with `Content-Security-Policy-Report-Only` first. |
| 9.2 | Host allow-lists are weak (any script on that host, including JSONP endpoints, is allowed). | Prefer nonces + `'strict-dynamic'`; add Subresource Integrity (`integrity="sha384-…"`) on third-party scripts. |
| 9.3 | Swagger UI at `/api` needs inline scripts/styles and may break under the CSP; it also publicly documents the attack surface. | Disable Swagger in production or protect it with auth. |
| 9.4 | Make framing policy explicit. | `frameAncestors: ["'none'"]` unless embedding is required. |
| 9.5 | `object-src`, `base-uri`, `form-action` are left to defaults. | Set `objectSrc: ["'none'"]`, `baseUri: ["'self'"]`, `formAction: ["'self'"]`. |
| 9.6 | CSP is defence-in-depth. The real XSS fix is output encoding. | Article `title`/`content` are stored raw; any HTML consumer must escape them (or sanitize with DOMPurify if rich text is required). |

---

## 10. Cross-cutting issues found in the codebase

These are not tied to a single lab step but matter just as much.

### 10.1 Sensitive data exposure — password hashes in responses (High)

- `GET /users` returns full `User` entities **including the `password` hash**.
- `POST /users/register` returns the saved entity, again with the hash.
- `Article.user` is `eager: true`, so **every `GET /articles` response embeds each
  author's password hash** — visible to any authenticated user.

**Fix:** never return entities directly. Either map to response DTOs, or:

```ts
// user.entity.ts
@Column({ select: false })
@Exclude()
password: string;

// main.ts
app.useGlobalInterceptors(new ClassSerializerInterceptor(app.get(Reflector)));
```

`select: false` also means the hash is only loaded when explicitly requested
(`addSelect('user.password')` in `findByUsername`).

### 10.2 Input validation gaps (Medium)

- `ValidationPipe({ whitelist: true, transform: true })` is good — it strips unknown
  properties. Add `forbidNonWhitelisted: true` to reject them loudly.
- `minLength: 6` exists only in the **Swagger annotation**, not as a validator. Add
  `@MinLength(12)` (NIST 800-63B recommends ≥ 8, prefer longer) and `@MaxLength(72)` —
  bcrypt silently ignores bytes beyond 72.
- Add `@MaxLength` to `username`, `title`, `content` to bound storage and processing.
- Set a JSON body limit (`app.useBodyParser('json', { limit: '100kb' })`).

### 10.3 Error handling leaks internals (Medium)

[articles.controller.ts](src/articles/articles.controller.ts) wraps every error in
`new InternalServerErrorException(error.message)`, which:

- sends raw DB/driver messages to the client (schema and query details), and
- turns a legitimate `NotFoundException` into a `500`.

**Fix:** let `HttpException`s propagate, and add a global exception filter that logs the
real error server-side and returns a generic message for unknown errors.

### 10.4 Database configuration (Medium)

- `synchronize: true` in [app.module.ts](src/app.module.ts) lets TypeORM alter the
  schema at startup — it can drop columns/data in production and conflicts with the
  migrations in `src/migrations`. Set it to `false` and use migrations only.
- Use a least-privilege DB user for the app (no `DROP`/`ALTER`), and a separate one for
  migrations.
- `compose.yaml` falls back to the password `newsroom`. Require it via `${DB_PASS:?}` so a
  missing value fails loudly. (Binding Postgres to `127.0.0.1` is already done — good.)
- TypeORM's repository API is parameterised, which prevents SQL injection; keep it that
  way and never build raw queries with string concatenation.

### 10.5 Dependencies / supply chain (Medium)

- `crypto` in `package.json` is a deprecated npm placeholder — Node's built-in `crypto`
  is what the code actually uses. Remove it: unnecessary packages are attack surface.
- `csurf` is deprecated (see 7.1). `passport`, `passport-jwt`, `@nestjs/passport` and
  `cheerio` appear unused at runtime — remove or move to `devDependencies`.
- Run `npm audit`, enable Dependabot/Renovate, and commit the lockfile (already done).

### 10.6 Configuration & secrets

- `.env` is correctly git-ignored and `.env.example` contains placeholders — good.
- Validate all config at startup with a schema so the app refuses to boot with missing or
  weak values.
- In production load secrets from a secret manager (AWS Secrets Manager, Vault, Doppler)
  rather than files.

### 10.7 Logging & monitoring

- Replace `console.error` with Nest's `Logger` (or pino) and structured logs.
- Log security events: failed logins, 401/403/429 spikes, role changes, CSRF failures,
  CSP reports. Never log passwords, tokens or full cookies.

### 10.8 Transport

- Serve only over HTTPS; Helmet's HSTS header only has effect over TLS.
- If behind a load balancer, configure `trust proxy` correctly (affects rate limiting,
  `secure` cookies and `req.ip`).

---

## 11. Prioritised improvement backlog

| Priority | Item | Section |
|----------|------|---------|
| 🔴 Critical | Remove `role` from public registration | 5.1 |
| 🔴 High | Stop returning password hashes (`/users`, `/register`, eager `Article.user`) | 10.1 |
| 🔴 High | Throttle `/auth/login` and `/users/register` | 6.1 |
| 🔴 High | Deny-by-default global guards + `@Public()` | 3 |
| 🟠 Medium | Generic login errors + constant-time path | 2.1, 2.2 |
| 🟠 Medium | `secure` + `sameSite` cookies, don't return token in body, add logout | 4.x |
| 🟠 Medium | Replace deprecated `csurf`; keep one CSRF mechanism | 7.1, 7.2 |
| 🟠 Medium | `synchronize: false`, migrations only | 10.4 |
| 🟠 Medium | Stop leaking `error.message`; global exception filter | 10.3 |
| 🟠 Medium | Real password validators (`@MinLength`, `@MaxLength`) | 10.2 |
| 🟡 Low | Pin JWT algorithm, add `iss`/`aud`, check `Bearer` scheme | 2.3–2.5 |
| 🟡 Low | `getAllAndOverride` in `RolesGuard`, `ParseIntPipe` | 5.2, 5.5 |
| 🟡 Low | Remove `@SkipThrottle()` from DELETE; Redis throttler storage | 6.2, 6.3 |
| 🟡 Low | CSP reporting, `frame-ancestors 'none'`, disable Swagger in prod | 9.x |
| 🟡 Low | Remove unused/deprecated dependencies, enable `npm audit` in CI | 10.5 |

---

## 12. General security principles to take away

1. **Deny by default.** Public access should be the explicit exception, not the
   accidental result of a forgotten decorator.
2. **Authentication ≠ Authorization.** "Who are you?" (401) and "are you allowed?" (403)
   are separate checks — and authorization includes *object ownership*, not just roles.
3. **Never trust client input** — not the body, not the role the user claims, not the
   `Origin` header. Validate on the server with whitelists.
4. **Defence in depth.** SameSite cookies + CSRF tokens + Origin checks; output encoding
   + CSP; rate limiting + account lockout. Each layer covers the others' gaps.
5. **Least privilege** for users, tokens (short TTL, minimal claims), DB accounts, and
   dependencies.
6. **Fail securely and quietly.** Errors should be generic to the client and detailed in
   the logs. Config errors should stop the app from starting.
7. **Minimise what you return.** Responses are an API contract — use DTOs, never raw
   entities.
8. **Every control has a trade-off.** Cookies fix XSS token theft but introduce CSRF;
   CORS relaxes the same-origin policy; `@SkipThrottle` removes protection. Know what you
   are trading.
9. **Keep dependencies alive.** Deprecated security libraries (like `csurf`) stop
   receiving fixes; audit and update continuously.
10. **Map to OWASP.** The issues above correspond to OWASP Top 10: A01 Broken Access
    Control (5.1, 3, 5.4), A02 Cryptographic Failures (4.1, 10.1), A04 Insecure Design
    (2.7), A05 Security Misconfiguration (10.4, 9.x), A06 Vulnerable Components (10.5),
    A07 Identification & Authentication Failures (2.x, 6.1), A09 Logging & Monitoring
    Failures (10.7).
