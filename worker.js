// FocusFlow Cloudflare Worker: wallet creation, balance, coin spend, refund and history.
//
// Worker configuration (set in the Cloudflare dashboard or with wrangler; NEVER put values here):
//   FIREBASE_SERVICE_ACCOUNT_JSON  secret  Service-account key JSON. Role: "Cloud Datastore User".
//   FIREBASE_API_KEY               secret  Firebase Web API key, used to verify ID tokens.
//                                          FIREBASE_WEB_API_KEY is accepted as an alias.
//   FIREBASE_PROJECT_ID            var     Optional. Defaults to resourceswebsite-4871a.
//   UNITY_S2S_SECRET               secret  Random secret (at least 32 chars) for the reward callback.
//   PDF_TOKEN_SECRET               secret  Random secret (at least 32 chars) for short-lived PDF tokens.
//
// Security model:
// - Every wallet route needs "Authorization: Bearer <Firebase ID token>". Google verifies the token.
// - The user id comes only from the verified token. The client never sends a uid.
// - Prices are defined here. The client sends only an action name.
// - Balances change only inside Firestore transactions, and only through this Worker.
// - Charges and refunds are keyed by requestId, so retries cannot charge or refund twice.

export const PRICES = Object.freeze({ view: 30, download: 65, share: 75 });

const DEFAULT_PROJECT_ID = "resourceswebsite-4871a";
const REQUEST_ID_RE = /^[A-Za-z0-9_-]{16,64}$/;
const RESOURCE_ID_RE = /^[A-Za-z0-9_-]{1,128}$/;
const MAX_TX_ATTEMPTS = 5;
const HISTORY_DEFAULT = 20;
const HISTORY_MAX = 50;
const DATASTORE_SCOPE = "https://www.googleapis.com/auth/datastore";
const TOKEN_URL = "https://oauth2.googleapis.com/token";
const TOKEN_TTL_SECONDS = 5 * 60;
const LOOKUP_URL = "https://identitytoolkit.googleapis.com/v1/accounts:lookup";
const FIRESTORE_ROOT = "https://firestore.googleapis.com/v1";
// Firestore codes that mean "another request changed the data first": retry from a fresh read.
const CONTENTION = new Set(["ABORTED", "ALREADY_EXISTS", "FAILED_PRECONDITION"]);

// ---------- errors ----------

export class ConfigError extends Error {}
export class InvariantError extends Error {}
export class ContentionError extends Error {}

// ---------- small helpers ----------

export function json(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

export function resolveConfig(env = {}) {
  return {
    projectId: env.FIREBASE_PROJECT_ID || DEFAULT_PROJECT_ID,
    apiKey: env.FIREBASE_API_KEY || env.FIREBASE_WEB_API_KEY || "",
    serviceAccountJson: env.FIREBASE_SERVICE_ACCOUNT_JSON || "",
    unityS2sSecret: env.UNITY_S2S_SECRET || "",
    pdfTokenSecret: env.PDF_TOKEN_SECRET || "",
  };
}

function b64urlBytes(buffer) {
  const bytes = new Uint8Array(buffer);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlString(str) {
  return b64urlBytes(new TextEncoder().encode(str));
}

function pemToDer(pem) {
  const b64 = String(pem).replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}

// ---------- Firestore REST value helpers ----------

export const intValue = (n) => ({ integerValue: String(n) });
export const strValue = (s) => ({ stringValue: String(s) });
export const readInt = (field) =>
  field && field.integerValue !== undefined ? Number(field.integerValue) : 0;
export const readStr = (field) =>
  field && field.stringValue !== undefined ? String(field.stringValue) : "";

// A wallet balance must be a non-negative safe integer. Anything else is a data error, so stop.
function walletBalance(fields) {
  if (!fields) return 0;
  const balance = readInt(fields.balance);
  if (!Number.isSafeInteger(balance) || balance < 0) throw new InvariantError("wallet balance invalid");
  return balance;
}

// ---------- Firebase ID token verification (Google verifies the token) ----------

export async function verifyIdToken(idToken, apiKey, fetchFn = fetch) {
  if (!apiKey) throw new ConfigError("web API key secret is missing");
  const res = await fetchFn(`${LOOKUP_URL}?key=${encodeURIComponent(apiKey)}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ idToken }),
  });
  if (res.status >= 500) throw new Error(`identity lookup failed with HTTP ${res.status}`);
  if (!res.ok) return null;
  const data = await res.json().catch(() => null);
  const user = data && Array.isArray(data.users) ? data.users[0] : null;
  if (!user || !user.localId || user.disabled) return null;
  return user.localId;
}

// ---------- Google service-account access token (cached until shortly before expiry) ----------

let cachedAccess = null;

export async function getServiceAccessToken(serviceAccountJson, fetchFn = fetch, nowMs = Date.now()) {
  let sa;
  try {
    sa = JSON.parse(serviceAccountJson || "");
  } catch {
    throw new ConfigError("service account secret is not valid JSON");
  }
  if (!sa || !sa.client_email || !sa.private_key) throw new ConfigError("service account secret is incomplete");

  if (cachedAccess && cachedAccess.email === sa.client_email && cachedAccess.expiresAt - 60_000 > nowMs) {
    return cachedAccess.token;
  }

  const iat = Math.floor(nowMs / 1000);
  const unsigned =
    b64urlString(JSON.stringify({ alg: "RS256", typ: "JWT" })) +
    "." +
    b64urlString(
      JSON.stringify({
        iss: sa.client_email,
        scope: DATASTORE_SCOPE,
        aud: TOKEN_URL,
        iat,
        exp: iat + 3600,
      })
    );

  let key;
  try {
    key = await crypto.subtle.importKey(
      "pkcs8",
      pemToDer(sa.private_key),
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["sign"]
    );
  } catch {
    throw new ConfigError("service account private key is invalid");
  }
  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(unsigned));

  const res = await fetchFn(TOKEN_URL, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: `${unsigned}.${b64urlBytes(signature)}`,
    }),
  });
  if (!res.ok) throw new Error(`service token exchange failed with HTTP ${res.status}`);
  const data = await res.json();
  if (!data.access_token) throw new Error("service token exchange returned no token");

  cachedAccess = {
    email: sa.client_email,
    token: data.access_token,
    expiresAt: nowMs + (data.expires_in ? data.expires_in * 1000 : 3_600_000),
  };
  return data.access_token;
}

// ---------- Firestore REST client ----------

// Maps a batchGet response onto the requested paths.
// The REST API returns a JSON array with one entry per document: {found: {name, fields}} or {missing: name}.
// Entries can arrive in any order, so match them by document name, not by position.
export function mapBatchGet(items, paths, docsRoot) {
  if (!Array.isArray(items)) throw new Error("batchGet response is not an array");
  const prefix = `${docsRoot}/`;
  const byPath = new Map();
  for (const item of items) {
    if (item && item.found) {
      const name = item.found.name || "";
      if (!name.startsWith(prefix)) throw new Error("batchGet returned an unexpected document name");
      byPath.set(name.slice(prefix.length), item.found.fields || {});
    } else if (item && item.missing) {
      if (!String(item.missing).startsWith(prefix)) throw new Error("batchGet returned an unexpected missing name");
      byPath.set(String(item.missing).slice(prefix.length), null);
    }
  }
  return paths.map((p) => {
    if (!byPath.has(p)) throw new Error(`batchGet gave no answer for ${p}`);
    return byPath.get(p);
  });
}

export function makeFirestoreRest({ projectId, getAccessToken, fetchFn = fetch }) {
  const docsRoot = `projects/${projectId}/databases/(default)/documents`;
  // Firestore REST custom methods are written with a colon: .../documents:commit (not .../documents/commit).
  const base = `${FIRESTORE_ROOT}/${docsRoot}`;

  async function post(method, body) {
    const token = await getAccessToken();
    const res = await fetchFn(`${base}:${method}`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const text = await res.text();
    if (!res.ok) {
      let status = "";
      try {
        status = (JSON.parse(text).error || {}).status || "";
      } catch {
        status = "";
      }
      const err = new Error(`firestore ${method} failed with HTTP ${res.status}`);
      err.status = res.status;
      err.firestoreStatus = status;
      throw err;
    }
    try {
      return text ? JSON.parse(text) : {};
    } catch {
      throw new Error(`firestore ${method} returned invalid JSON`);
    }
  }

  return {
    docsRoot,

    async beginTransaction() {
      const data = await post("beginTransaction", { options: { readWrite: {} } });
      if (!data.transaction) throw new Error("beginTransaction returned no transaction");
      return data.transaction;
    },

    // paths are relative to the documents root, e.g. "users/<uid>/wallet/main".
    async batchGet(paths, transaction) {
      const body = { documents: paths.map((p) => `${docsRoot}/${p}`) };
      if (transaction) body.transaction = transaction;
      const items = await post("batchGet", body);
      return mapBatchGet(items, paths, docsRoot);
    },

    // writes: [{ path, fields, updateMask?: string[], precondition?: "mustNotExist" | "mustExist" }]
    async commit(writes, transaction) {
      const fsWrites = writes.map((w) => {
        const write = { update: { name: `${docsRoot}/${w.path}`, fields: w.fields } };
        if (w.updateMask) write.updateMask = { fieldPaths: w.updateMask };
        if (w.precondition === "mustNotExist") write.currentDocument = { exists: false };
        if (w.precondition === "mustExist") write.currentDocument = { exists: true };
        return write;
      });
      return post("commit", { writes: fsWrites, transaction });
    },

    // Returns [{ name, fields }] for documents matching the query under parentPath.
    async runQuery(parentPath, structuredQuery) {
      const items = await post("runQuery", { parent: `${docsRoot}/${parentPath}`, structuredQuery });
      return items
        .filter((i) => i && i.document)
        .map((i) => ({ name: i.document.name, fields: i.document.fields || {} }));
    },
  };
}

// Runs fn in a Firestore transaction and retries only on contention.
// fn(fs, txId) returns { status, body, writes }. Business outcomes return with writes: [].
export async function runTransaction(fs, fn) {
  for (let attempt = 0; attempt < MAX_TX_ATTEMPTS; attempt++) {
    const txId = await fs.beginTransaction();
    const result = await fn(fs, txId);
    if (!result.writes || result.writes.length === 0) return result;
    try {
      await fs.commit(result.writes, txId);
      return result;
    } catch (e) {
      if (!CONTENTION.has(e.firestoreStatus)) throw e;
      // Another request changed the same data. Start again from a fresh read.
    }
  }
  throw new ContentionError("transaction contention");
}

// ---------- signed PDF access tokens and Unity reward callback ----------

function constantTimeEqual(a, b) {
  const x = new TextEncoder().encode(String(a));
  const y = new TextEncoder().encode(String(b));
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

async function hmacBytes(secret, message) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message)));
}

function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

async function makePdfToken(secret, payload) {
  const encoded = b64urlString(JSON.stringify(payload));
  return `${encoded}.${bytesToHex(await hmacBytes(secret, encoded))}`;
}

async function verifyPdfToken(secret, token) {
  if (!secret || typeof token !== "string" || token.length > 2048) return null;
  const dot = token.lastIndexOf(".");
  if (dot <= 0) return null;
  const encoded = token.slice(0, dot);
  const supplied = token.slice(dot + 1);
  const expected = bytesToHex(await hmacBytes(secret, encoded));
  if (!constantTimeEqual(supplied, expected)) return null;
  try {
    const payload = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(encoded.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((encoded.length + 3) % 4)), c => c.charCodeAt(0))));
    if (!payload || !Number.isInteger(payload.exp) || payload.exp < Math.floor(Date.now() / 1000)) return null;
    if (typeof payload.uid !== "string" || typeof payload.resourceId !== "string") return null;
    return payload;
  } catch {
    return null;
  }
}

export async function handlePdfAccessToken(request, deps) {
  const uid = await authenticate(request, deps);
  if (!uid) return json(401, { ok: false, error: "unauthenticated" });
  if (!deps.pdfTokenSecret || deps.pdfTokenSecret.length < 32) {
    throw new ConfigError("PDF_TOKEN_SECRET must be configured with at least 32 characters");
  }
  const body = await readJson(request);
  if (!body || typeof body.resourceId !== "string" || !RESOURCE_ID_RE.test(body.resourceId)) {
    return json(400, { ok: false, error: "invalid_resource" });
  }
  const now = Math.floor(Date.now() / 1000);
  const token = await makePdfToken(deps.pdfTokenSecret, {
    uid, resourceId: body.resourceId, iat: now, exp: now + TOKEN_TTL_SECONDS,
  });
  return json(200, { ok: true, token, expiresIn: TOKEN_TTL_SECONDS, resourceId: body.resourceId });
}

// Validates a short-lived token. PDF storage/delivery must be connected separately;
// this endpoint intentionally does not fetch arbitrary URLs or expose private storage.
export async function handlePdfDeliver(request, deps) {
  if (!deps.pdfTokenSecret || deps.pdfTokenSecret.length < 32) {
    throw new ConfigError("PDF_TOKEN_SECRET must be configured with at least 32 characters");
  }
  const body = await readJson(request);
  const payload = body && await verifyPdfToken(deps.pdfTokenSecret, body.token);
  if (!payload) return json(401, { ok: false, error: "invalid_or_expired_token" });
  return json(501, {
    ok: false,
    error: "pdf_storage_not_configured",
    message: "Token validated. Configure a private PDF storage source before enabling file delivery.",
    resourceId: payload.resourceId,
  });
}

export async function handleUnityRewardCallback(request, deps) {
  if (!deps.unityS2sSecret || deps.unityS2sSecret.length < 32) {
    throw new ConfigError("UNITY_S2S_SECRET must be configured with at least 32 characters");
  }
  const supplied = request.headers.get("x-unity-secret") || "";
  if (!constantTimeEqual(supplied, deps.unityS2sSecret)) {
    return json(401, { ok: false, error: "invalid_callback_secret" });
  }
  const body = await readJson(request);
  if (!body || typeof body.uid !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(body.uid)) {
    return json(400, { ok: false, error: "invalid_uid" });
  }
  const rewardId = body.rewardId;
  if (typeof rewardId !== "string" || !/^[A-Za-z0-9_-]{16,128}$/.test(rewardId)) {
    return json(400, { ok: false, error: "invalid_reward_id" });
  }
  // Reward amount is server-defined; callers cannot choose the number of coins.
  const rewardAmount = 25;
  const uid = body.uid;
  const wallet = `users/${uid}/wallet/main`;
  const txPath = `users/${uid}/coinTransactions/unity_${rewardId}`;
  const result = await runTransaction(deps.firestore, async (fs, txId) => {
    const [walletFields, existingTx] = await fs.batchGet([wallet, txPath], txId);
    if (existingTx) {
      return { status: 200, body: { ok: true, idempotent: true, rewarded: false, amount: 0 }, writes: [] };
    }
    const balance = walletBalance(walletFields);
    const newBalance = balance + rewardAmount;
    if (!Number.isSafeInteger(newBalance)) {
      return { status: 409, body: { ok: false, error: "wallet_balance_overflow" }, writes: [] };
    }
    const now = Date.now();
    const writes = [];
    if (walletFields) writes.push(balanceWrite(wallet, newBalance, now));
    else writes.push({ path: wallet, precondition: "mustNotExist", fields: {
      balance: intValue(newBalance), createdAt: intValue(now), updatedAt: intValue(now), schemaVersion: intValue(1),
    }});
    writes.push({ path: txPath, precondition: "mustNotExist", fields: {
      type: strValue("rewarded_ad"), action: strValue("unity_reward"), amount: intValue(rewardAmount),
      rewardId: strValue(rewardId), balanceAfter: intValue(newBalance), createdAt: intValue(now),
    }});
    return { status: 200, body: { ok: true, idempotent: false, rewarded: true, amount: rewardAmount, balance: newBalance }, writes };
  });
  return json(result.status, result.body);
}

// ---------- paths ----------

function walletPaths(uid) {
  return { wallet: `users/${uid}/wallet/main` };
}
function coinPaths(uid, requestId) {
  return {
    wallet: `users/${uid}/wallet/main`,
    req: `users/${uid}/coinRequests/${requestId}`,
    tx: `users/${uid}/coinTransactions/${requestId}`,
    refundTx: `users/${uid}/coinTransactions/refund_${requestId}`,
  };
}

// Only these three fields change on a balance update. The update mask leaves everything else alone.
const BALANCE_MASK = ["balance", "updatedAt", "schemaVersion"];
function balanceWrite(path, newBalance, now) {
  return {
    path,
    updateMask: BALANCE_MASK,
    fields: { balance: intValue(newBalance), updatedAt: intValue(now), schemaVersion: intValue(1) },
  };
}

// ---------- auth ----------

function bearerToken(request) {
  const m = /^Bearer\s+(\S+)$/i.exec(request.headers.get("authorization") || "");
  return m ? m[1] : null;
}

async function authenticate(request, deps) {
  const token = bearerToken(request);
  if (!token) return null;
  return deps.verifyIdToken(token);
}

// ---------- /auth-check ----------

export async function handleAuthCheck(request, deps) {
  const uid = await authenticate(request, deps);
  if (!uid) return json(401, { ok: false, error: "unauthenticated" });
  return json(200, { ok: true, uid });
}

// ---------- /ensure-wallet: creates the wallet at 0 coins if missing. Never grants coins. ----------

export async function handleEnsureWallet(request, deps) {
  const uid = await authenticate(request, deps);
  if (!uid) return json(401, { ok: false, error: "unauthenticated" });

  const paths = walletPaths(uid);
  const result = await runTransaction(deps.firestore, async (fs, txId) => {
    const [wallet] = await fs.batchGet([paths.wallet], txId);
    if (wallet) {
      return { status: 200, body: { ok: true, created: false, balance: walletBalance(wallet) }, writes: [] };
    }
    const now = Date.now();
    return {
      status: 200,
      body: { ok: true, created: true, balance: 0 },
      writes: [
        {
          path: paths.wallet,
          precondition: "mustNotExist",
          fields: {
            balance: intValue(0),
            createdAt: intValue(now),
            updatedAt: intValue(now),
            schemaVersion: intValue(1),
          },
        },
      ],
    };
  });
  return json(result.status, result.body);
}

// ---------- /balance: read only. A missing wallet reads as 0. ----------

export async function handleBalance(request, deps) {
  const uid = await authenticate(request, deps);
  if (!uid) return json(401, { ok: false, error: "unauthenticated" });

  const [wallet] = await deps.firestore.batchGet([walletPaths(uid).wallet], null);
  return json(200, { ok: true, exists: wallet !== null, balance: walletBalance(wallet) });
}

// ---------- /spend-coins ----------

export async function handleSpend(request, deps) {
  const uid = await authenticate(request, deps);
  if (!uid) return json(401, { ok: false, error: "unauthenticated" });

  const body = await readJson(request);
  if (!body || typeof body !== "object") return json(400, { ok: false, error: "invalid_body" });
  const { action, resourceId, requestId } = body;
  if (!Object.prototype.hasOwnProperty.call(PRICES, action)) return json(400, { ok: false, error: "invalid_action" });
  if (typeof resourceId !== "string" || !RESOURCE_ID_RE.test(resourceId)) {
    return json(400, { ok: false, error: "invalid_resource" });
  }
  if (typeof requestId !== "string" || !REQUEST_ID_RE.test(requestId)) {
    return json(400, { ok: false, error: "invalid_request_id" });
  }

  const price = PRICES[action];
  const paths = coinPaths(uid, requestId);

  const result = await runTransaction(deps.firestore, async (fs, txId) => {
    const [walletFields, reqFields] = await fs.batchGet([paths.wallet, paths.req], txId);

    if (reqFields) {
      // Same requestId again (retry, timeout, screen recreated). Never charge twice.
      if (readStr(reqFields.action) !== action || readStr(reqFields.resourceId) !== resourceId) {
        return { status: 409, body: { ok: false, error: "request_conflict" }, writes: [] };
      }
      return {
        status: 200,
        body: {
          ok: true,
          idempotent: true,
          action,
          price,
          balance: readInt(reqFields.balanceAfter),
          status: readStr(reqFields.status),
          transactionId: requestId,
        },
        writes: [],
      };
    }

    const balance = walletBalance(walletFields);
    if (balance < price) {
      return { status: 402, body: { ok: false, error: "insufficient_balance", balance, price }, writes: [] };
    }

    const newBalance = balance - price;
    const now = Date.now();
    return {
      status: 200,
      body: {
        ok: true,
        idempotent: false,
        status: "charged",
        action,
        price,
        balance: newBalance,
        transactionId: requestId,
      },
      writes: [
        balanceWrite(paths.wallet, newBalance, now),
        {
          path: paths.tx,
          precondition: "mustNotExist",
          fields: {
            type: strValue("spend"),
            action: strValue(action),
            amount: intValue(-price),
            resourceId: strValue(resourceId),
            balanceAfter: intValue(newBalance),
            createdAt: intValue(now),
          },
        },
        {
          path: paths.req,
          precondition: "mustNotExist",
          fields: {
            action: strValue(action),
            resourceId: strValue(resourceId),
            price: intValue(price),
            balanceAfter: intValue(newBalance),
            status: strValue("charged"),
            createdAt: intValue(now),
          },
        },
      ],
    };
  });
  return json(result.status, result.body);
}

// ---------- /refund-coins: refunds a charged request exactly once ----------

export async function handleRefund(request, deps) {
  const uid = await authenticate(request, deps);
  if (!uid) return json(401, { ok: false, error: "unauthenticated" });

  const body = await readJson(request);
  if (!body || typeof body !== "object") return json(400, { ok: false, error: "invalid_body" });
  const { requestId } = body;
  const reason = typeof body.reason === "string" ? body.reason.slice(0, 80) : "";
  if (typeof requestId !== "string" || !REQUEST_ID_RE.test(requestId)) {
    return json(400, { ok: false, error: "invalid_request_id" });
  }

  const paths = coinPaths(uid, requestId);

  const result = await runTransaction(deps.firestore, async (fs, txId) => {
    const [walletFields, reqFields] = await fs.batchGet([paths.wallet, paths.req], txId);

    if (!reqFields) return { status: 404, body: { ok: false, error: "request_not_found" }, writes: [] };

    const status = readStr(reqFields.status);
    if (status === "refunded") {
      // Already refunded: report it and change nothing.
      return {
        status: 200,
        body: {
          ok: true,
          idempotent: true,
          refunded: true,
          status: "refunded",
          balance: readInt(reqFields.refundedBalance),
        },
        writes: [],
      };
    }
    if (status !== "charged") {
      return { status: 409, body: { ok: false, error: "not_refundable", status }, writes: [] };
    }

    const price = readInt(reqFields.price);
    if (price <= 0) return { status: 409, body: { ok: false, error: "not_refundable" }, writes: [] };

    // A charged request without its wallet is an inconsistent state. Do not
    // silently recreate the wallet and credit coins during a refund.
    if (!walletFields) {
      return { status: 409, body: { ok: false, error: "wallet_missing" }, writes: [] };
    }

    const balance = walletBalance(walletFields);
    const newBalance = balance + price;
    if (!Number.isSafeInteger(newBalance)) {
      return { status: 409, body: { ok: false, error: "wallet_balance_overflow" }, writes: [] };
    }
    const now = Date.now();
    return {
      status: 200,
      body: { ok: true, idempotent: false, refunded: true, status: "refunded", price, balance: newBalance },
      writes: [
        balanceWrite(paths.wallet, newBalance, now),
        {
          path: paths.refundTx,
          precondition: "mustNotExist",
          fields: {
            type: strValue("refund"),
            action: strValue(readStr(reqFields.action)),
            amount: intValue(price),
            resourceId: strValue(readStr(reqFields.resourceId)),
            originalRequestId: strValue(requestId),
            reason: strValue(reason),
            balanceAfter: intValue(newBalance),
            createdAt: intValue(now),
          },
        },
        {
          path: paths.req,
          precondition: "mustExist",
          updateMask: ["status", "refundedAt", "refundedBalance"],
          fields: {
            status: strValue("refunded"),
            refundedAt: intValue(now),
            refundedBalance: intValue(newBalance),
          },
        },
      ],
    };
  });
  return json(result.status, result.body);
}

// ---------- /transactions: the caller's own coin history, newest first ----------

export async function handleTransactions(request, deps) {
  const uid = await authenticate(request, deps);
  if (!uid) return json(401, { ok: false, error: "unauthenticated" });

  const body = (await readJson(request)) || {};
  let limit = HISTORY_DEFAULT;
  if (body.limit !== undefined) {
    if (!Number.isInteger(body.limit) || body.limit < 1 || body.limit > HISTORY_MAX) {
      return json(400, { ok: false, error: "invalid_limit" });
    }
    limit = body.limit;
  }

  const rows = await deps.firestore.runQuery(`users/${uid}`, {
    from: [{ collectionId: "coinTransactions" }],
    orderBy: [{ field: { fieldPath: "createdAt" }, direction: "DESCENDING" }],
    limit,
  });

  const transactions = rows.map((row) => {
    const f = row.fields;
    return {
      id: row.name.split("/").pop(),
      type: readStr(f.type),
      action: readStr(f.action),
      amount: readInt(f.amount),
      resourceId: readStr(f.resourceId),
      balanceAfter: readInt(f.balanceAfter),
      createdAt: readInt(f.createdAt),
    };
  });
  return json(200, { ok: true, transactions });
}

// ---------- errors and production wiring ----------

function errorResponse(e) {
  if (e instanceof ContentionError) return json(409, { ok: false, error: "busy_retry" });
  if (e instanceof ConfigError) {
    console.error("configuration error:", e.message);
    return json(500, { ok: false, error: "server_misconfigured" });
  }
  if (e instanceof InvariantError) {
    console.error("data invariant:", e.message);
    return json(500, { ok: false, error: "wallet_invalid" });
  }
  console.error("worker error:", String(e && e.message));
  return json(500, { ok: false, error: "internal_error" });
}

export function makeProdDeps(env, fetchFn = fetch) {
  const cfg = resolveConfig(env);
  return {
    verifyIdToken: (idToken) => verifyIdToken(idToken, cfg.apiKey, fetchFn),
    unityS2sSecret: cfg.unityS2sSecret,
    pdfTokenSecret: cfg.pdfTokenSecret,
    firestore: makeFirestoreRest({
      projectId: cfg.projectId,
      getAccessToken: () => getServiceAccessToken(cfg.serviceAccountJson, fetchFn),
      fetchFn,
    }),
  };
}

const ROUTES = {
  "/auth-check": handleAuthCheck,
  "/ensure-wallet": handleEnsureWallet,
  "/balance": handleBalance,
  "/spend-coins": handleSpend,
  "/refund-coins": handleRefund,
  "/transactions": handleTransactions,
  "/unity-reward-callback": handleUnityRewardCallback,
  "/pdf-access-token": handlePdfAccessToken,
  "/pdf-deliver": handlePdfDeliver,
};

export async function route(request, deps) {
  const url = new URL(request.url);
  try {
    if (request.method === "GET" && url.pathname === "/health") {
      return json(200, { ok: true, service: "FocusFlow Backend", status: "running" });
    }
    if (request.method === "GET" && url.pathname === "/firebase-check") {
      // Proves the service account can reach Firestore. Returns no project or key details.
      await deps.firestore.batchGet(["_healthcheck/ping"], null);
      return json(200, { ok: true, firestore: "reachable" });
    }
    const handler = ROUTES[url.pathname];
    if (!handler) return json(404, { ok: false, error: "not_found" });
    if (request.method !== "POST") return json(405, { ok: false, error: "method_not_allowed" });
    return await handler(request, deps);
  } catch (e) {
    return errorResponse(e);
  }
}

export default {
  async fetch(request, env) {
    return route(request, makeProdDeps(env));
  },
};
