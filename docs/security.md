# Security Architecture

## Introduction

PRFC Connect is a web application I built for the Paso Robles Food Co-op, a member-owned grocery cooperative. The application tracks member referrals and sends group email and text messages to members. It stores the names, email addresses, and phone numbers of about 389 members. Because that data identifies real people, every request has to prove who is asking and what they may do before the database is touched. Protecting it comes down to two goals from the CIA triad. Confidentiality keeps the wrong people from reading it, and integrity keeps the wrong people from changing it.

This report explains the security architecture and shows, with code, how the application defends against the most common web risks. I organize the defenses around the OWASP Top 10:2025, a widely used list of the ten most common web application risks. First I describe the general architecture. Then I walk through small pieces of code that cover the session, access control, and each of the five core defenses. After that I summarize how the remaining OWASP categories are handled, state the limitations honestly, and document how the next student team takes the project over.

The thesis is that a request moves through four gates that run in order. First it authenticates the user, then it authorizes the action, then it validates the input, and last it reaches the database. Each gate runs on its own, so if one gate has a bug, the others still block the request. This is defense in depth.

## The four-gate request path

The application is built on Next.js, and it keeps a strict separation between code that runs in the browser and code that runs on the server. The server code is split into layers. Pages fetch data and hand it to client components. Server actions accept a request, check the session, validate the input, and call a service. Services own all database access and are marked `server-only`, so the bundler refuses to ship them to the browser. This layering matters because it gives every database write one predictable path to travel through.

A member deleting a contact group shows the four gates in action. First, the proxy at [`src/proxy.ts`](../src/proxy.ts) checks that a session cookie is present and redirects to `/unauthorized` if it is not. Then the server action runs `verifySession()` as its first line, which rejects anyone without a valid signed cookie. Next, the action checks ownership, so a member cannot delete a group that belongs to someone else. Then a Zod schema validates the input. Only after all four checks pass does the service run the Prisma query. The data access layer is the real boundary, because it runs even when the proxy is bypassed.

This design follows several well-known security principles. Checking the session and ownership on every request, with no trusted path around the data access layer, is complete mediation. Rejecting a request the moment a gate fails, instead of letting it through, is fail-safe defaults. The cookie format is public and only the signing key stays secret, which is open design rather than security by obscurity. And the four independent gates are defense in depth.

## The session is a signed cookie

The application keeps no session table. Instead, the session is a single cookie whose value is signed proof of identity. The format is `ownerid|isAdmin|timestamp|signature`, and the signature is the first eight hex characters of an HMAC-SHA256 over the first three fields. An HMAC is a message authentication code. Because it mixes in a secret key, it proves two things a plain hash cannot, that the fields are unchanged (integrity) and that they came from the server (authenticity). It also resists the length-extension trick that can fool a raw hash. Because the signature depends on a server-side secret, a user cannot forge or edit the cookie without breaking it.

The function that proves a cookie is genuine lives in [`src/lib/dal.ts`](../src/lib/dal.ts).

```ts
export function validateToken(token: string, secret: string): Session | null {
  const parts = token.split("|");
  if (parts.length !== 4) return null;

  const [ownerid, isAdmin, timestamp, signature] = parts;
  if (!ownerid || !isAdmin || !timestamp || !signature) return null;

  const payload = `${ownerid}|${isAdmin}|${timestamp}`;
  if (!verifyHmac(payload, signature, secret)) return null;

  const tokenTime = parseInt(timestamp, 10);
  if (isNaN(tokenTime) || tokenTime > Date.now() || Date.now() - tokenTime > TOKEN_EXPIRY_MS) return null;

  const parsedOwnerId = parseInt(ownerid, 10);
  if (isNaN(parsedOwnerId) || parsedOwnerId <= 0) return null;

  return { ownerid: parsedOwnerId, isAdmin: isAdmin === "1" };
}
```

The signature is verified first, so a tampered cookie never reaches the timestamp logic. Then the timestamp is checked against a one-hour window, so a stolen cookie stops working after sixty minutes. Finally the owner id is parsed and bounded, so a malformed value is rejected rather than trusted. Every server action calls `verifySession()`, which reads the cookie and runs this function, so this one check stands in front of the entire authenticated surface of the app. Because the proof lives in the cookie and nowhere else, there is nothing on the server for an attacker to steal.

## Access control

The session proves who you are. Access control decides what you may do. Every server action runs an authorization check after `verifySession()` and before it touches the database. The check in [`src/actions/contact-group.ts`](../src/actions/contact-group.ts) is typical.

```ts
if (!session.isAdmin && !(await isGroupOwner(validGroupId, session.ownerid))) {
  console.error("[ACCESS_DENIED] deleteContactGroup", session.ownerid, validGroupId);
  return { success: false, error: "You do not have permission to delete this group" };
}
```

This is role-based access control with record ownership. An administrator may act on any group, a member may act only on the groups they own, and everyone else is denied by default. The rule behind it is least privilege, so each user gets the smallest set of rights the task needs. A member who learns another group's id still cannot change it, because the ownership check runs on the server, not in the browser. Together the session check and these authorization checks are the first two parts of AAA, authentication and authorization. The third part, accounting, is the audit log described later.

## Five defenses

### 1. Session lifecycle

Authentication is delegated to the co-op's member portal, which hands this application a signed token on login. The callback route in [`src/app/api/auth/callback/route.ts`](../src/app/api/auth/callback/route.ts) turns that token into a cookie.

```ts
response.cookies.set(AUTH_COOKIE, token, {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax",
  maxAge: 3600,
  path: "/",
});
```

The `logout()` server action in [`src/actions/auth.ts`](../src/actions/auth.ts) deletes the same cookie when the member logs out.

```ts
export async function logout() {
  const cookieStore = await cookies();
  cookieStore.delete(AUTH_COOKIE);
  redirect("/dev/mock-portal");
}
```

Login sets a one-hour cookie, every request carries it automatically, and logout deletes it. The next request to a protected page then redirects to `/unauthorized` because no cookie is present. The application stores no password, so whole classes of password attacks do not apply to it.

### 2. Cookie security

The cookie's attributes limit the damage if it leaks. `HttpOnly` keeps JavaScript from reading it, `SameSite=lax` keeps the browser from sending it on cross-site form posts, and `Secure` keeps it off plain HTTP in production. The signature does the rest of the work, because it makes the cookie tamper-evident. `verifyHmac` performs that check.

```ts
function verifyHmac(payload: string, signature: string, secret: string): boolean {
  if (signature.length !== 8) return false;

  const expected = createHmac("sha256", secret).update(payload).digest("hex").slice(0, 8);

  return timingSafeEqual(Buffer.from(signature, "utf8"), Buffer.from(expected, "utf8"));
}
```

The application recomputes the expected signature from the payload and compares it with the one in the cookie. If an attacker flips the `isAdmin` field from `0` to `1` to become an administrator, the payload changes, the expected signature no longer matches, and `validateToken` returns null. The comparison uses `timingSafeEqual` rather than `===`, because a plain comparison returns faster on an early-byte mismatch, and that timing difference can leak the correct signature one byte at a time. Therefore the constant-time comparison closes a side channel that a naive check would leave open. Without the signature, the cookie would flip as easily as changing a plain `loggedin=0` value to `loggedin=1`. The signature is what turns that edit into a dead end.

### 3. Cross-site scripting

Cross-site scripting happens when user input is rendered as HTML and the browser runs it as code. The application avoids this in two ways. First, React escapes any value placed in JSX by default, so a message body rendered as `<p>{message.body}</p>` is treated as text, not markup. Second, for email, where React is not involved, the server escapes the input itself. The function lives in [`src/utils/html.ts`](../src/utils/html.ts).

```ts
const HTML_ESCAPE_MAP: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#x27;",
};

const HTML_ESCAPE_RE = /[&<>"']/g;

export function escapeHtml(str: string): string {
  return str.replace(HTML_ESCAPE_RE, (char) => HTML_ESCAPE_MAP[char]);
}
```

A payload like `<script>alert('xss')</script>` becomes `&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;`, which the browser shows as literal characters and never runs. Because the application never calls `dangerouslySetInnerHTML`, no path turns user text back into live markup.

### 4. SQL injection

SQL injection happens when user input is concatenated into a query string and the database runs part of it as SQL. The application does not build query strings at all. It uses the Prisma ORM, which binds every value as a parameter. The create call in [`src/services/contact-group.ts`](../src/services/contact-group.ts) is representative.

```ts
export async function createGroup(data: CreateContactGroup, ownerid: number): Promise<ContactGroup> {
  try {
    return await prisma.contactGroup.create({
      data: { name: data.name, description: data.description, ownerid },
    });
  } catch (error) {
    throw transformError(error);
  }
}
```

Here `data.name` is passed as a value, not spliced into text. So a group named `'; DROP TABLE ContactGroup; --` is stored as that exact literal string, and the table is untouched. The codebase contains no raw SQL calls, no `$queryRaw`, and no `$executeRaw`, so no place exists where this guarantee can quietly break.

### 5. Cross-site request forgery

Cross-site request forgery tricks a logged-in user's browser into sending a request the user did not intend, using the cookie the browser attaches automatically. The application rejects such requests by checking where they came from. The check is in [`src/lib/csrf.ts`](../src/lib/csrf.ts).

```ts
export function validateOrigin(req: NextRequest): boolean {
  const secFetchSite = req.headers.get("sec-fetch-site");
  if (secFetchSite === "cross-site") return false;
  if (secFetchSite === "same-origin" || secFetchSite === "same-site") return true;

  const origin = req.headers.get("origin");
  const host = req.headers.get("host");
  if (!origin || !host) return false;

  return origin === `https://${host}` || origin === `http://${host}`;
}
```

The function reads `Sec-Fetch-Site` first, because the browser sets that header and page JavaScript cannot forge it. A value of `cross-site` is rejected outright. When that header is missing, the function compares the `Origin` header against the request's own host. So a POST from `https://evil-site.com` is refused with 403 even when it carries a valid session cookie. The state-changing API routes run this check right after authentication and before any data is read, so a forged request fails early.

## The remaining categories, in brief

The five mechanisms above are the application's primary defenses. The rest of the OWASP Top 10:2025 is addressed too, more briefly.

- **Security Misconfiguration (A02)** is handled in [`next.config.ts`](../next.config.ts), which sets a Content-Security-Policy, HSTS, an `X-Frame-Options` deny rule, a content-type nosniff rule, a Referrer-Policy, and a Permissions-Policy on every response. Errors return structured JSON through `transformError`, which strips stack traces and database details before they reach the client.
- **Software Supply Chain Failures (A03)** are limited by a committed lock file with integrity hashes, a clean `npm audit`, and pinned [`package.json`](../package.json) overrides for transitive fixes. The runtime and frameworks are current, running Node 22, Next.js 16, Prisma 7, and React 19.
- **Cryptographic Failures (A04)** cover more than the signed cookie above. Stored PII in the referral, suppression, and consent tables is encrypted at rest with AES-256-GCM, which is authenticated encryption that draws a fresh IV from a secure random generator for every value, so identical inputs never produce identical ciphertext. Lookups use a keyed HMAC blind index instead of the raw value.
- **Insecure Design (A06)** is addressed by controls that are design choices. Rate limiters cap login, referral, member-lookup, and message-send traffic at five requests per sixty seconds. A daily email quota of 300 is enforced with an atomic Redis INCRBY, so two concurrent sends cannot both slip under the limit. An idempotency key with Redis SET NX stops a double-submitted referral form from creating duplicates. Photo uploads check the file's magic bytes and a 2 MB ceiling on the server.
- **Authentication Failures (A07)** are covered above. The one-hour token, the rate-limited callback, and an identical redirect for valid and invalid tokens, which prevents account enumeration, all live here.
- **Software or Data Integrity Failures (A08)** are limited because Zod schemas strip unknown fields, so an attacker cannot smuggle extra properties into a database write. The HMAC cookie gives the session integrity, and no third-party scripts load from a CDN at runtime.
- **Security Logging and Alerting Failures (A09)** are the weakest area. Every security-relevant event uses a prefixed log line such as `[AUTH_CALLBACK]`, `[ACCESS_DENIED]`, `[AUDIT]`, and `[EMAIL_SEND_ERROR]`, so the events are grep-able. However, the Vercel Hobby plan keeps logs for only about an hour and sends no alerts, so the limitations section below treats this honestly.
- **Mishandling of Exceptional Conditions (A10)** is handled by centralizing error handling in `transformError` and by failing closed. The cron endpoint rejects requests when `CRON_SECRET` is unset, `getSecret()` throws in production when its secret is missing, and the email sender marks recipients as `queued` rather than `failed` when the quota runs out, so no message is lost.

## Limitations

A secure design should state what it does not do. PRFC Connect runs on the Vercel Hobby plan, which keeps function logs for only about an hour and offers no alerting. The prefixed log lines help during a live investigation, but they disappear soon after, and nothing pages a human when `[ACCESS_DENIED]` spikes. There is no formal incident-response playbook beyond a documented manual procedure. There is also no automated SAST or DAST step in continuous integration, secret rotation is manual, and multi-factor authentication is the portal's responsibility, not this application's. These gaps do not undermine the request-path defenses, but a production deployment for a larger membership should close them.

## Handoff to the next team

This project will pass to a future student team, so I document where the security lives and the one rule that keeps it intact.

A few files hold the security-relevant code. [`src/lib/dal.ts`](../src/lib/dal.ts) holds session validation and the admin gate. [`src/lib/csrf.ts`](../src/lib/csrf.ts) holds the origin check. [`src/lib/encryption.ts`](../src/lib/encryption.ts) holds the AES-256-GCM field encryption for stored PII. [`src/lib/rate-limit.ts`](../src/lib/rate-limit.ts), [`src/lib/idempotency.ts`](../src/lib/idempotency.ts), and [`src/lib/email-quota.ts`](../src/lib/email-quota.ts) hold the abuse controls. [`src/utils/html.ts`](../src/utils/html.ts) holds the HTML escaper used in email rendering, and [`src/app/api/auth/callback/route.ts`](../src/app/api/auth/callback/route.ts) holds the cookie-issuing callback. [`next.config.ts`](../next.config.ts) holds the response headers, and [`src/proxy.ts`](../src/proxy.ts) holds the cookie redirect.

The application also depends on secrets that must be set in the deployment environment and rotated periodically. These are `PRFC_PORTAL_SECRET`, `FIELD_ENCRYPTION_KEY`, `BLIND_INDEX_KEY`, `UNSUBSCRIBE_SECRET`, `CRON_SECRET`, the Upstash Redis credentials, the Brevo and Twilio keys, and the Vercel Blob token. None of these belong in the repository.

The rule to preserve is the four-gate path. Every new server action calls `verifySession()` first, validates its input with a Zod schema, checks record ownership before it mutates anything, and reaches the database only through a `server-only` service. The team should never write raw SQL, never call `dangerouslySetInnerHTML`, and always keep `validateOrigin` on state-changing API routes. So long as new features follow that pattern, they inherit the existing defenses.

I recommend three operational improvements first. Forward logs to a service that retains them and can alert (for example Axiom or Datadog), write a short incident-response playbook, and add a dependency-audit step to continuous integration.

## Conclusion

PRFC Connect protects member data by sending every request through four independent gates before it reaches the database. The session is a signed cookie that the server can verify but a user cannot forge. Tampering breaks the signature, user input renders as text instead of code, the ORM binds every query value as a parameter, and a foreign origin is refused even with a valid cookie. Each gate is simple on its own. Together they keep one mistake from becoming a breach. That matters because the data belongs to the members of a small nonprofit, and the application exists to protect it.

## References

- OWASP Top 10:2025. https://owasp.org/Top10/2025/
- PRFC Connect source code, files cited inline by path.
