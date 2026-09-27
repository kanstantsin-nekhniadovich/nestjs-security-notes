# NestJS Security Guide

A practical guide to securing NestJS applications, and web APIs in general. Each section
explains what the control is, why it exists, how to put it in place in NestJS, and the
mistakes people commonly make with it.

---

## Table of contents

1. [The request pipeline: where each control belongs](#1-the-request-pipeline-where-each-control-belongs)
2. [Authentication: passwords and JWTs](#2-authentication-passwords-and-jwts)
3. [Where to store the token: header vs cookie](#3-where-to-store-the-token-header-vs-cookie)
4. [Authorization: deny by default, roles and ownership](#4-authorization-deny-by-default-roles-and-ownership)
5. [Input validation](#5-input-validation)
6. [Output: don't leak sensitive data](#6-output-dont-leak-sensitive-data)
7. [Error handling](#7-error-handling)
8. [Rate limiting](#8-rate-limiting)
9. [CSRF protection](#9-csrf-protection)
10. [CORS](#10-cors)
11. [Security headers and Content Security Policy](#11-security-headers-and-content-security-policy)
12. [Database security](#12-database-security)
13. [Configuration and secrets](#13-configuration-and-secrets)
14. [Dependencies and supply chain](#14-dependencies-and-supply-chain)
15. [Logging and monitoring](#15-logging-and-monitoring)
16. [Transport and deployment](#16-transport-and-deployment)
17. [Hardening checklist](#17-hardening-checklist)
18. [General principles](#18-general-principles)

---

## 1. The request pipeline: where each control belongs

Every NestJS security control runs at a particular stage of the request lifecycle. If you
know the order, you know where a control belongs:

```
Incoming request
  │
  ├─ Express/Fastify middleware (app.use)  → helmet, CORS, cookie parsing, CSRF, CSP nonce
  ├─ Nest middleware (NestMiddleware)      → route-scoped middleware
  ├─ Guards (CanActivate)                  → rate limiting, authentication, authorization
  ├─ Interceptors (before handler)         → logging, timing
  ├─ Pipes                                 → validation and transformation (ValidationPipe, ParseIntPipe)
  ├─ Route handler
  ├─ Interceptors (after handler)          → response serialization (strip secrets)
  └─ Exception filters                     → turn errors into safe HTTP responses
```

- **Middleware** deals with transport-level concerns (headers, cookies, CORS, CSRF) that
  don't depend on which handler will run.
- **Guards** decide "may this request reach the handler?". They can read the
  `ExecutionContext`, so they can see route metadata such as `@Roles()` or `@Public()`.
- **Pipes** decide "is this input well-formed?".
- **Interceptors and exception filters** control what leaves the server.

---

## 2. Authentication: passwords and JWTs

### 2.1 Password storage

- Never store plain-text passwords, and never use a fast hash such as MD5 or SHA-256 for
  them. Use a slow, salted password-hashing algorithm: **Argon2id** (OWASP's first
  choice) or **bcrypt** with a cost factor of at least 12.
- Compare with the library's own verify function (`bcrypt.compare`, `argon2.verify`).
  These functions handle the salt and run in constant time.
- bcrypt silently ignores input beyond **72 bytes**, so enforce a maximum password length
  (or use Argon2id instead).
- Enforce password length with a real validator (`@MinLength(12)`). A `minLength` in
  Swagger/OpenAPI metadata is documentation only and validates nothing.

### 2.2 Don't reveal which accounts exist

A login endpoint leaks information in two ways:

1. **Different error messages.** "User not found" and "Wrong password" tell an attacker
   which usernames are valid. Always return one generic message, such as
   `Invalid credentials`.
2. **Different response times.** If the handler skips the password hash when the user
   doesn't exist, that path is measurably faster. Hash against a dummy value so both paths
   take the same time.

```ts
import { randomBytes } from 'crypto';
import * as bcrypt from 'bcryptjs';

// Computed once at startup: a valid hash that no real password will match.
const DUMMY_HASH = bcrypt.hashSync(randomBytes(32).toString('hex'), 12);

async login(username: string, password: string) {
  const user = await this.usersService.findByUsernameWithPassword(username);
  const valid = await bcrypt.compare(password, user?.password ?? DUMMY_HASH);

  if (!user || !valid) {
    throw new UnauthorizedException('Invalid credentials');
  }

  return this.jwtService.signAsync({ sub: user.id, role: user.role });
}
```

The same rule applies to registration and password-reset endpoints. For example, "Email
already registered" also reveals which accounts exist, so return a neutral response there
too.

### 2.3 JSON Web Tokens

A JWT is a **bearer credential**: whoever holds it is treated as that user until it
expires. It is signed, not encrypted, so anyone holding it can read the payload.

**Configure `JwtModule` from validated configuration, never from hard-coded values:**

```ts
JwtModule.registerAsync({
  inject: [ConfigService],
  useFactory: (config: ConfigService) => ({
    secret: config.getOrThrow<string>('JWT_SECRET'),
    signOptions: {
      expiresIn: config.getOrThrow<string>('JWT_EXPIRATION'), // e.g. '15m'
      issuer: 'my-api',
      audience: 'my-frontend',
    },
    verifyOptions: {
      algorithms: ['HS256'], // pin the algorithm
      issuer: 'my-api',
      audience: 'my-frontend',
    },
  }),
}),
```

Best practices:

| Practice | Why |
|----------|-----|
| Use a secret of at least 256 random bits, loaded from a secret store | Short HMAC secrets can be brute-forced offline from any captured token. |
| Pin the accepted `algorithms` | Prevents algorithm-confusion attacks (`alg: none`, RS256→HS256). |
| Set and verify `iss` and `aud` | Stops a token minted for another service with the same key from being accepted. |
| Use short-lived access tokens (5–15 min) | Limits how long a stolen token can be used. |
| Use rotating refresh tokens stored server-side | Lets you revoke sessions and log users out for real. |
| Keep claims minimal (`sub`, `role`) and never put secrets or personal data in them | The payload is only base64url-encoded, so anyone can read it. |
| Don't set `iat` by hand | The library sets it correctly. |
| Let `JwtService` use its module config when verifying | Re-reading the secret elsewhere (possibly as `undefined`) causes subtle bugs. |

**A minimal authentication guard:**

```ts
@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(private readonly jwt: JwtService, private readonly reflector: Reflector) {}

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      ctx.getHandler(),
      ctx.getClass(),
    ]);
    if (isPublic) return true;

    const req = ctx.switchToHttp().getRequest<Request>();
    const [type, token] = req.headers.authorization?.split(' ') ?? [];
    if (type !== 'Bearer' || !token) throw new UnauthorizedException();

    try {
      req.user = await this.jwt.verifyAsync(token);
    } catch {
      throw new UnauthorizedException();
    }
    return true;
  }
}
```

Note that the guard checks the `Bearer` scheme explicitly. Taking whatever sits after the
first space accepts malformed headers.

**Revocation.** A plain JWT cannot be revoked. If a user logs out, changes their password,
or loses a role, their existing token stays valid until it expires. Mitigations:

- short access-token TTL plus server-side refresh tokens that you can delete;
- a `tokenVersion` column on the user, embedded in the token and compared on each request;
- a deny-list of revoked `jti` values in Redis.

---

## 3. Where to store the token: header vs cookie

| Storage | Can XSS steal the token? | Is CSRF possible? |
|---------|---------------------------|-------------------|
| `localStorage` + `Authorization: Bearer` header | **Yes**: any injected script can read it | No: the browser never attaches it automatically |
| `httpOnly` cookie | No: JavaScript cannot read it | **Yes**: the browser attaches it automatically (see [§9](#9-csrf-protection)) |

Neither option is free. Cookies are generally preferred for browser clients, but they
**require** CSRF defences. Bearer headers suit non-browser clients (mobile, server to
server).

### Secure cookie settings

```ts
@Post('login')
async login(@Body() dto: LoginDto, @Res({ passthrough: true }) res: Response) {
  const token = await this.authService.login(dto.username, dto.password);

  res.cookie('__Host-access_token', token, {
    httpOnly: true,                                  // not readable by JS
    secure: true,                                    // HTTPS only
    sameSite: 'strict',                              // not sent on cross-site requests
    path: '/',
    maxAge: this.config.getOrThrow<number>('JWT_TTL_MS'), // same source as the JWT expiry
  });

  return { success: true }; // do NOT also return the token in the body
}

@Post('logout')
logout(@Res({ passthrough: true }) res: Response) {
  res.clearCookie('__Host-access_token', { path: '/', secure: true, sameSite: 'strict' });
  // also revoke the refresh token server-side
}
```

Key points:

- `httpOnly`, `secure` and `sameSite` should all be set explicitly.
- If you **return the token in the response body as well**, frontend code will usually
  store it somewhere readable, which cancels out the benefit of `httpOnly`.
- The `__Host-` prefix makes the browser enforce `Secure`, `Path=/` and no `Domain`
  attribute. This blocks cookie injection from subdomains.
- Derive the cookie's `maxAge` and the JWT's `expiresIn` from the same config value so they
  can't drift apart.
- Prefer `@Res({ passthrough: true })`. A bare `@Res()` switches Nest to library-specific
  mode, so interceptors and the normal return-value handling are bypassed.
- Register `cookie-parser` (`app.use(cookieParser())`) so `req.cookies` is populated.

---

## 4. Authorization: deny by default, roles and ownership

**Authentication** answers "who are you?" and fails with `401 Unauthorized`.
**Authorization** answers "are you allowed to do this?" and fails with `403 Forbidden`.
Both are required, and authentication must run first so that `request.user` exists.

### 4.1 Deny by default

If every route has to opt in with `@UseGuards(JwtAuthGuard)`, any route where someone
forgets it is public. This is the most common source of **broken access control**
(OWASP A01). Instead, register the guards globally and mark the few public routes
explicitly:

```ts
// public.decorator.ts
export const IS_PUBLIC_KEY = 'isPublic';
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);

// app.module.ts: global guards run in the order they are registered
providers: [
  { provide: APP_GUARD, useClass: ThrottlerGuard },
  { provide: APP_GUARD, useClass: JwtAuthGuard },
  { provide: APP_GUARD, useClass: RolesGuard },
],

// auth.controller.ts
@Public()
@Post('login')
login() { /* ... */ }
```

### 4.2 Role-based access control (RBAC)

```ts
// roles.decorator.ts
export const ROLES_KEY = 'roles';
export const Roles = (...roles: Role[]) => SetMetadata(ROLES_KEY, roles);

// roles.guard.ts
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(ctx: ExecutionContext): boolean {
    const required = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [
      ctx.getHandler(), // method-level @Roles() wins...
      ctx.getClass(),   // ...otherwise fall back to controller-level @Roles()
    ]);
    if (!required?.length) return true;

    const { user } = ctx.switchToHttp().getRequest();
    if (!user || !required.includes(user.role)) {
      throw new ForbiddenException();
    }
    return true;
  }
}
```

Common mistakes:

- **`reflector.get(KEY, ctx.getHandler())` only reads method metadata.** A `@Roles()` on the
  controller class is silently ignored. Use `getAllAndOverride` (or `getAllAndMerge`).
- **Letting users choose their own role.** If a public registration DTO accepts a `role`
  field, anyone can sign up as `admin` and RBAC is meaningless. Always assign the lowest
  role on sign-up and change roles only through a privileged endpoint. This is a form of
  **mass assignment**.
- **Trusting a stale role in the token.** A demoted admin keeps `role: admin` until their
  token expires. Use short TTLs, or load the current role from the DB or a cache in the
  guard.

### 4.3 Object-level authorization (ownership)

RBAC answers "can editors delete articles?". It cannot answer "can *this* editor delete
*this* article?". Without an ownership check, any user who guesses an ID can act on
someone else's data. This vulnerability is called **IDOR** (Insecure Direct Object
Reference), or BOLA in OWASP's API Top 10.

```ts
async deleteArticle(id: number, user: AuthUser) {
  const article = await this.repo.findOne({ where: { id }, relations: { author: true } });
  if (!article) throw new NotFoundException();
  if (user.role !== Role.Admin && article.author.id !== user.sub) {
    throw new ForbiddenException();
  }
  await this.repo.remove(article);
}
```

For complex rules, use a policy library such as **CASL** instead of scattering `if`
statements.

---

## 5. Input validation

Register a global `ValidationPipe` with strict options:

```ts
app.useGlobalPipes(
  new ValidationPipe({
    whitelist: true,             // strip properties that have no decorators
    forbidNonWhitelisted: true,  // ...and reject the request instead of silently stripping
    transform: true,             // turn payloads into DTO class instances
  }),
);
```

Guidelines:

- Put a validator on **every** DTO field, and bound every string with `@MaxLength()` to
  limit storage and processing cost.
- Use `@IsEnum()` for fixed sets of values and `@IsInt()`/`@Min()` for numbers.
- Validate path and query params too: `@Param('id', ParseIntPipe) id: number`. For
  example, `Number('abc')` gives `NaN` rather than an error.
- Keep separate DTOs for separate operations (`CreateUserDto`, `AdminUpdateUserDto`), so
  that privileged fields can never be set through public endpoints.
- Limit request body size, for example
  `app.useBodyParser('json', { limit: '100kb' })` on a `NestExpressApplication`.
- Validation isn't output encoding. Stored text must still be escaped wherever it is
  rendered (see [§11](#11-security-headers-and-content-security-policy)).

---

## 6. Output: don't leak sensitive data

Returning ORM entities directly is one of the most common data leaks. Password hashes,
internal flags and related entities end up in responses. Eager-loaded relations make it
worse: an article that eagerly loads its author also returns that author's hash.

**Option A: explicit response DTOs** (the most robust approach):

```ts
return users.map((u) => ({ id: u.id, username: u.username, role: u.role }));
```

**Option B: class-transformer serialization.**

```ts
// user.entity.ts
@Column({ select: false }) // not loaded unless explicitly requested
@Exclude()                 // never serialized even if loaded
password: string;

// main.ts
app.useGlobalInterceptors(new ClassSerializerInterceptor(app.get(Reflector)));

// where the hash is genuinely needed (login):
this.repo.createQueryBuilder('u').addSelect('u.password').where('u.username = :username', { username }).getOne();
```

`ClassSerializerInterceptor` only affects **class instances**, so plain objects
(`{ ...user }`) bypass `@Exclude()`.

Also avoid eager relations unless you really need them, and never return tokens,
secrets, or internal IDs that clients have no use for.

---

## 7. Error handling

A common anti-pattern:

```ts
catch (error) {
  throw new InternalServerErrorException(error.message); // ❌
}
```

This has two problems:

1. It sends raw database or driver messages to the client, which exposes table names,
   constraints and query fragments.
2. It turns meaningful `HttpException`s (such as `NotFoundException`) into `500`s.

Better:

- Let `HttpException`s propagate unchanged.
- Add a global exception filter that logs the full error server-side and returns a
  generic message for anything unexpected:

```ts
@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new Logger(AllExceptionsFilter.name);

  catch(exception: unknown, host: ArgumentsHost) {
    const res = host.switchToHttp().getResponse<Response>();
    if (exception instanceof HttpException) {
      return res.status(exception.getStatus()).json(exception.getResponse());
    }
    this.logger.error(exception);
    res.status(500).json({ statusCode: 500, message: 'Internal server error' });
  }
}
```

- Never expose stack traces in production.

---

## 8. Rate limiting

Rate limiting mitigates brute-force login, credential stuffing, scraping and cheap
application-level DoS. In NestJS, use `@nestjs/throttler`:

```ts
// app.module.ts
ThrottlerModule.forRoot([{ ttl: 60_000, limit: 100 }]), // ttl is in milliseconds (v5+)
providers: [{ provide: APP_GUARD, useClass: ThrottlerGuard }],

// stricter limit on sensitive endpoints
@Throttle({ default: { limit: 5, ttl: 60_000 } })
@Post('login')
login() { /* ... */ }

// exempt only what really needs it (e.g. health checks)
@SkipThrottle()
@Get('health')
health() { /* ... */ }
```

Guidelines:

- **Apply limits globally** and make them strictest on authentication, registration,
  password reset and anything that sends email or SMS.
- Don't `@SkipThrottle()` destructive or expensive endpoints.
- The default in-memory store is per-process and resets on restart. With more than one
  instance, use a shared store (for example Redis via `@nest-lab/throttler-storage-redis`).
- Behind a reverse proxy every request appears to come from the proxy's IP. Configure
  `app.set('trust proxy', <hops>)` correctly, or override `getTracker()` to key on the
  user ID for authenticated routes.
- Per-IP limits are easy to get around by rotating IPs. Add per-account throttling or
  exponential backoff after failed logins, and alert on spikes.

---

## 9. CSRF protection

### What CSRF is

When authentication relies on something the browser sends **automatically** (cookies,
HTTP Basic auth), a malicious site can make the victim's browser send authenticated
requests to your API. Your API can't tell those requests apart from genuine ones.

APIs authenticated purely by an `Authorization` header set from JavaScript are **not**
vulnerable to CSRF, because browsers never attach that header automatically.

### Defences (use several)

1. **`SameSite` cookies.** `SameSite=Strict` or `Lax` stops the browser sending the cookie
   on cross-site sub-requests. This is the strongest single measure, but it doesn't
   protect against attacks from sibling subdomains (same *site*, different *origin*).
2. **Anti-CSRF tokens.**
   - *Synchronizer token*: the server stores a token in the session and the client sends
     it back in a header (for example `X-CSRF-Token`).
   - *Signed double-submit cookie*: the server sets a token in a cookie and the client
     echoes it in a header. The token must be **signed or tied to the session**; an
     unsigned double-submit can be defeated by cookie injection.
   - An attacker can make the browser *send* cookies but cannot *read* the token, so they
     can't forge the header.
3. **Origin checks.** On unsafe methods, reject requests whose `Origin` (or
   `Sec-Fetch-Site`) header isn't in your allow-list.
4. **Never change state on `GET`.** CSRF middleware normally skips safe methods
   (`GET`, `HEAD`, `OPTIONS`), so a state-changing `GET` has no protection at all.

### Library choice

The once-popular `csurf` package is **deprecated and unmaintained**, so don't use it in
new code. Maintained alternatives include `csrf-csrf` (signed double-submit for Express)
and `@fastify/csrf-protection`. Use one mechanism consistently. Two overlapping
implementations with different cookie options are hard to reason about.

---

## 10. CORS

### What CORS actually does

By default, the browser's **same-origin policy** stops JavaScript on `site-a.com` from
reading responses from `api.site-b.com`. CORS lets a server **relax** that restriction for
specific origins.

- CORS is **not** access control for your API. It only tells browsers which origins may
  *read* responses. Tools like `curl` and server-side scripts ignore it completely.
- A request that CORS "blocks" is often still **sent and executed**; only reading the
  response is blocked. So CORS doesn't replace CSRF protection.

### Configuration

```ts
app.enableCors({
  origin: config.getOrThrow<string>('CORS_ORIGINS').split(','), // explicit allow-list
  methods: ['GET', 'POST', 'PUT', 'DELETE'],                    // only what you use
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
  credentials: true,  // needed only if the browser must send cookies cross-origin
  maxAge: 600,        // cache preflight responses
});
```

Common mistakes:

- `app.enableCors()` with no options allows **every** origin.
- Reflecting the request's `Origin` back unconditionally while also using
  `credentials: true` lets any website make authenticated reads of your API.
- Allowing `null` as an origin (sandboxed iframes and `file://` pages send it).
- Loose regexes such as `/example\.com$/`, which also match `evil-example.com`.

---

## 11. Security headers and Content Security Policy

### Helmet

`helmet` sets a set of protective HTTP headers in one call:

| Header | Protects against |
|--------|------------------|
| `Content-Security-Policy` | XSS and injection of scripts, styles, frames |
| `Strict-Transport-Security` | Protocol downgrade and SSL stripping (only effective over HTTPS) |
| `X-Content-Type-Options: nosniff` | MIME-type confusion |
| `X-Frame-Options` / `frame-ancestors` | Clickjacking |
| `Referrer-Policy` | Leaking URLs to third parties |
| `Cross-Origin-Opener/Resource-Policy` | Cross-origin data leaks |
| *(removes)* `X-Powered-By` | Technology fingerprinting |

### Content Security Policy

CSP tells the browser which sources of scripts, styles, fonts, frames and so on are
allowed. By default it blocks **inline scripts, inline event handlers (`onclick="…"`),
inline styles, `eval`, and any source not listed**.

There are three ways to allow a specific resource:

| Method | Example | Notes |
|--------|---------|-------|
| **Host allow-list** | `script-src https://cdn.example.com` | Weakest: *any* script on that host is allowed, including JSONP endpoints or user uploads. |
| **Nonce** | `script-src 'nonce-R4nd0m'` + `<script nonce="R4nd0m">` | A fresh cryptographically random value on every response. Must never be reused or predictable. |
| **Hash** | `style-src 'sha256-…'` | Allows one exact inline block. Changing a single character breaks it. |

A per-request nonce in NestJS:

```ts
// nonce.middleware.ts
@Injectable()
export class CspNonceMiddleware implements NestMiddleware {
  use(_req: Request, res: Response, next: NextFunction) {
    res.locals.cspNonce = randomBytes(16).toString('base64');
    next();
  }
}

// main.ts (the nonce middleware must run before helmet)
app.use(new CspNonceMiddleware().use);
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", (_req, res: Response) => `'nonce-${res.locals.cspNonce}'`],
        styleSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
      },
    },
  }),
);
```

Guidelines:

- Prefer **nonces or hashes** (optionally with `'strict-dynamic'`) over host allow-lists.
- Add **Subresource Integrity** (`integrity="sha384-…"`) to third-party scripts and
  stylesheets, so a compromised CDN can't swap in malicious code.
- Always set `object-src 'none'`, `base-uri 'self'` and `frame-ancestors`.
- Roll out a new policy with `Content-Security-Policy-Report-Only` and a `report-to` /
  `report-uri` endpoint first, fix the violations, then enforce it.
- Tools such as Swagger UI need their own relaxed policy. Better still, don't expose API
  docs publicly in production.
- CSP is **defence in depth**. The primary XSS defence is still context-aware output
  encoding (templating engines, React's JSX escaping). Sanitize user-provided HTML with a
  library such as DOMPurify.

---

## 12. Database security

- **Turn off schema auto-sync in production.** TypeORM's `synchronize: true` alters the
  schema on startup and can drop columns and data. Use versioned **migrations** instead.
- **Use parameterised queries.** ORM repository methods and QueryBuilder with `:params`
  are safe. Never build SQL by string concatenation or interpolation:

  ```ts
  // ❌ SQL injection
  repo.query(`SELECT * FROM users WHERE name = '${name}'`);
  // ✅ parameterised
  repo.createQueryBuilder('u').where('u.name = :name', { name }).getMany();
  ```

- **Grant least privilege.** The app's DB user needs only data access (no
  `DROP`/`ALTER`/superuser). Run migrations with a separate account.
- **Restrict the network.** Don't expose the database port publicly; bind it to
  localhost or a private network.
- **Fail when credentials are missing.** Defaults such as `${DB_PASS:-password}` in
  Compose files hide misconfiguration. Prefer `${DB_PASS:?DB_PASS is required}`.
- Encrypt connections (`ssl`) when the DB isn't on the same host, and encrypt backups.

---

## 13. Configuration and secrets

- Never commit secrets. Keep `.env` in `.gitignore` and commit only a `.env.example` with
  placeholders.
- **Validate configuration at startup** so the app refuses to boot with missing or weak
  values:

  ```ts
  ConfigModule.forRoot({
    isGlobal: true,
    validationSchema: Joi.object({
      NODE_ENV: Joi.string().valid('development', 'production', 'test').required(),
      JWT_SECRET: Joi.string().min(32).required(),
      DB_PASS: Joi.string().required(),
    }),
  });
  ```

- Use `configService.getOrThrow()` for required values instead of `get()`, which can
  silently return `undefined`.
- In production, load secrets from a secret manager (AWS Secrets Manager, GCP Secret
  Manager, HashiCorp Vault) and rotate them regularly.
- Use different secrets for each environment.

---

## 14. Dependencies and supply chain

- Remove unused packages; every dependency adds attack surface.
- Watch for **placeholder or look-alike packages**. For example, `crypto` on npm is a
  deprecated stub. Node's built-in `crypto` module needs no install.
- Replace **deprecated security libraries** (such as `csurf`), which no longer get fixes.
- Commit the lockfile and install with `npm ci` in CI.
- Run `npm audit` (or Snyk, or GitHub Dependabot) in CI, and automate updates with
  Renovate or Dependabot.
- Keep NestJS, Node.js and the ORM on supported versions.

---

## 15. Logging and monitoring

- Use Nest's `Logger` or a structured logger (pino, winston) instead of `console.*`.
- Log security-relevant events: failed and successful logins, `401`/`403`/`429` spikes,
  role and permission changes, CSRF failures, CSP violation reports, and admin actions.
- **Never log** passwords, tokens, full cookies, or other secrets and sensitive personal
  data.
- Send logs to a central system and alert on anomalies. Detecting an attack is part of
  defending against it (OWASP A09).

---

## 16. Transport and deployment

- Serve **only over HTTPS**. HSTS, `Secure` cookies and `__Host-` prefixes all depend on
  it.
- Behind a load balancer or reverse proxy, set `trust proxy` to the exact number of hops.
  It affects `req.ip`, rate limiting and `secure` cookie handling.
- Disable or protect API documentation (Swagger) in production.
- Run the process as a non-root user in a minimal container image.
- Set `NODE_ENV=production` and turn off debug features and verbose errors.

---

## 17. Hardening checklist

| Priority | Item |
|----------|------|
| 🔴 Critical | Users can't choose their own role or other privileged fields (mass assignment) |
| 🔴 Critical | Guards apply by default; public routes are explicitly marked `@Public()` |
| 🔴 High | Password hashes and other secrets never appear in responses (DTOs or `@Exclude` + `select: false`) |
| 🔴 High | Login, registration and password reset are rate-limited |
| 🔴 High | Object-level ownership checks on every resource accessed by ID |
| 🟠 Medium | Generic login errors with timing-equalised verification |
| 🟠 Medium | Auth cookies are `httpOnly`, `Secure`, `SameSite`, with no token in the response body, plus a logout endpoint |
| 🟠 Medium | CSRF protection with a maintained library, plus `SameSite` and Origin checks |
| 🟠 Medium | `synchronize: false` in production; migrations only |
| 🟠 Medium | Global exception filter; no raw error messages or stack traces to clients |
| 🟠 Medium | Strict `ValidationPipe`, length limits on every string, body size limit |
| 🟡 Low | JWT algorithm pinned, `iss`/`aud` verified, short TTL, revocation strategy |
| 🟡 Low | `getAllAndOverride` for role metadata; `ParseIntPipe` on numeric params |
| 🟡 Low | Shared rate-limit store and correct `trust proxy` in multi-instance deployments |
| 🟡 Low | CSP with nonces, `frame-ancestors 'none'`, reporting; Swagger off in production |
| 🟡 Low | Config validated at startup; secrets in a secret manager |
| 🟡 Low | Unused and deprecated dependencies removed; `npm audit` in CI |

---

## 18. General principles

1. **Deny by default.** Public access should be a deliberate exception, never the result
   of a forgotten decorator.
2. **Authentication ≠ authorization.** "Who are you?" (401) and "are you allowed?" (403)
   are separate checks, and authorization includes *object ownership*, not just roles.
3. **Never trust client input.** That includes the body, the role a user claims, IDs in
   the URL, and headers. Validate on the server against allow-lists.
4. **Use defence in depth.** SameSite cookies + CSRF tokens + Origin checks; output
   encoding + CSP; rate limiting + account lockout. Each layer covers gaps in the others.
5. **Apply least privilege** to users, tokens (short TTL, minimal claims), database
   accounts, containers and dependencies.
6. **Fail securely.** Clients get generic errors; logs get the details. Bad config should
   stop the app from starting.
7. **Return as little as possible.** Responses are a contract, so use DTOs, not raw
   entities.
8. **Know the trade-offs.** Cookies protect tokens from XSS but introduce CSRF. CORS
   relaxes the same-origin policy. Every exemption (`@SkipThrottle`, `@Public`) removes a
   protection.
9. **Keep dependencies maintained.** Abandoned security libraries stop receiving fixes.
10. **Map your controls to OWASP.** The OWASP Top 10 and the OWASP API Security Top 10 are
    good checklists: A01 Broken Access Control, A02 Cryptographic Failures, A03
    Injection, A04 Insecure Design, A05 Security Misconfiguration, A06 Vulnerable
    Components, A07 Identification & Authentication Failures, A09 Logging & Monitoring
    Failures.
