// FocusFlow coin spending. Prices live only on the server; the app sends an action name,
// a resource id and a unique requestId (idempotency key). Balances are never written by clients.
const { onCall, HttpsError } = require("firebase-functions/v2/https");
const admin = require("firebase-admin");
if (!admin.apps.length) admin.initializeApp();
const db = admin.firestore();

const PRICES = { view: 30, download: 50, share: 40 };
const REQUEST_ID_RE = /^[A-Za-z0-9_-]{16,64}$/;
const RESOURCE_ID_RE = /^[A-Za-z0-9_-]{1,128}$/;

exports.spendCoins = onCall({ region: "us-central1", maxInstances: 20 }, async (request) => {
  const uid = request.auth && request.auth.uid;
  if (!uid) throw new HttpsError("unauthenticated", "Sign in to use FocusFlow Coins.");

  const data = request.data || {};
  const action = data.action;
  const resourceId = data.resourceId;
  const requestId = data.requestId;

  if (!Object.prototype.hasOwnProperty.call(PRICES, action)) {
    throw new HttpsError("invalid-argument", "Unknown coin action.");
  }
  if (typeof resourceId !== "string" || !RESOURCE_ID_RE.test(resourceId)) {
    throw new HttpsError("invalid-argument", "Invalid resource id.");
  }
  if (typeof requestId !== "string" || !REQUEST_ID_RE.test(requestId)) {
    throw new HttpsError("invalid-argument", "Invalid request id.");
  }

  const price = PRICES[action];
  const userRef = db.collection("users").doc(uid);
  const walletRef = userRef.collection("wallet").doc("main");
  const reqRef = userRef.collection("coinRequests").doc(requestId);
  const txRef = userRef.collection("coinTransactions").doc(requestId);

  return db.runTransaction(async (tx) => {
    const reqSnap = await tx.get(reqRef);
    if (reqSnap.exists) {
      // Same request again (retry / screen recreated): never charge twice.
      if (reqSnap.get("action") !== action || reqSnap.get("resourceId") !== resourceId) {
        throw new HttpsError("invalid-argument", "This request id was used for a different action.");
      }
      return reqSnap.get("result");
    }

    const walletSnap = await tx.get(walletRef);
    const balance = walletSnap.exists ? Number(walletSnap.get("balance") || 0) : 0;
    if (balance < price) {
      throw new HttpsError("failed-precondition", "Not enough FocusFlow Coins.", { balance, price });
    }

    const newBalance = balance - price;
    const now = Date.now();
    const result = { ok: true, action, price, balance: newBalance, transactionId: requestId };

    tx.set(walletRef, { balance: newBalance, updatedAt: now }, { merge: true });
    tx.set(txRef, {
      type: "spend",
      action,
      amount: -price,
      resourceId,
      balanceAfter: newBalance,
      createdAt: now,
    });
    tx.set(reqRef, { action, resourceId, price, result, createdAt: now });
    return result;
  });
});
