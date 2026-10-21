
const PROJECT_ID = "resourceswebsite-4871a";

const PRICES = {
  view: 30,
  download: 50,
  share: 60
};

const REQUEST_ID_RE = /^[A-Za-z0-9_-]{16,64}$/;
const RESOURCE_ID_RE = /^[A-Za-z0-9_-]{1,128}$/;

function json(data, status = 200) {
  return Response.json(data, {
    status,
    headers: { "Cache-Control": "no-store" }
  });
}

function base64url(value) {
  const bytes = new TextEncoder().encode(
    typeof value === "string" ? value : JSON.stringify(value)
  );
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

async function getAccessToken(env) {
  const account = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT_JSON || "{}");

  if (!account.client_email || !account.private_key) {
    throw new Error("Invalid Firebase service-account secret");
  }

  const now = Math.floor(Date.now() / 1000);

  const unsigned =
    base64url({ alg: "RS256", typ: "JWT" }) + "." +
    base64url({
      iss: account.client_email,
      scope: "https://www.googleapis.com/auth/datastore",
      aud: "https://oauth2.googleapis.com/token",
      iat: now,
      exp: now + 3600
    });

  const pem = account.private_key.replace(
    /-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\s/g,
    ""
  );

  const key = await crypto.subtle.importKey(
    "pkcs8",
    Uint8Array.from(atob(pem), c => c.charCodeAt(0)),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(unsigned)
  );

  const assertion =
    unsigned + "." +
    btoa(String.fromCharCode(...new Uint8Array(signature)))
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");

  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion
    })
  });

  const result = await response.json();

  if (!response.ok) {
    throw new Error("Google authentication failed");
  }

  return result.access_token;
}

async function verifyUser(request, env) {
  const header = request.headers.get("Authorization") || "";

  if (!header.startsWith("Bearer ")) return null;

  if (!env.FIREBASE_WEB_API_KEY) {
    throw new Error("Missing FIREBASE_WEB_API_KEY secret");
  }

  const response = await fetch(
    `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${env.FIREBASE_WEB_API_KEY}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ idToken: header.slice(7) })
    }
  );

  const result = await response.json();

  if (!response.ok || !result.users?.[0]?.localId) return null;

  return result.users[0].localId;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/health") {
      return json({
        ok: true,
        service: "FocusFlow Backend",
        status: "running"
      });
    }

    if (request.method === "GET" && url.pathname === "/firebase-check") {
      try {
        const token = await getAccessToken(env);

        const response = await fetch(
          `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)`,
          {
            headers: {
              Authorization: `Bearer ${token}`
            }
          }
        );

        const result = await response.json();

        return json({
          ok: response.ok,
          firestoreStatus: response.status,
          database: result.name || null
        });
      } catch (error) {
        return json({
          ok: false,
          error: error.message || "Firebase connection failed"
        }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/auth-check") {
      try {
        const uid = await verifyUser(request, env);

        if (!uid) {
          return json({
            ok: false,
            error: "Invalid Firebase ID token"
          }, 401);
        }

        return json({ ok: true, uid });
      } catch (error) {
        return json({
          ok: false,
          error: error.message || "Authentication failed"
        }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/spend-coins") {
      try {
        const uid = await verifyUser(request, env);

        if (!uid) {
          return json({
            ok: false,
            error: "Sign in required"
          }, 401);
        }

        const body = await request.json();
        const { action, resourceId, requestId } = body;

        if (!Object.hasOwn(PRICES, action)) {
          return json({ ok: false, error: "Invalid action" }, 400);
        }

        if (
          typeof resourceId !== "string" ||
          !RESOURCE_ID_RE.test(resourceId)
        ) {
          return json({
            ok: false,
            error: "Invalid resourceId"
          }, 400);
        }

        if (
          typeof requestId !== "string" ||
          !REQUEST_ID_RE.test(requestId)
        ) {
          return json({
            ok: false,
            error: "Invalid requestId"
          }, 400);
        }

        // Safe fallback: no wallet changes until atomic
        // Firestore transaction support is implemented.
        return json({
          ok: false,
          enabled: false,
          action,
          price: PRICES[action],
          uid,
          error: "Coin spending is not enabled yet. No coins were deducted."
        }, 501);
      } catch (error) {
        return json({
          ok: false,
          error: error.message || "Request failed"
        }, 500);
      }
    }

    return json({
      ok: false,
      error: "Not found"
    }, 404);
  }
};
