// FocusFlow server-side notifications: pushes a short preview of every new Community message
// to the "community_chat" FCM topic. Runs with Admin privileges, so no keys live in the app.
const { onDocumentCreated } = require("firebase-functions/v2/firestore");
const { setGlobalOptions } = require("firebase-functions/v2");
const { logger } = require("firebase-functions");
const admin = require("firebase-admin");

admin.initializeApp();
const db = admin.firestore();
setGlobalOptions({ region: "us-central1", maxInstances: 10 });

// Coin spending callable (spendCoins)
exports.spendCoins = require("./coins").spendCoins;

const COMMUNITY_TOPIC = "community_chat";
const THROTTLE_MS = 20 * 1000; // at most one push per chat every 20 s (spam control)
const PREVIEW_MAX = 90;

exports.notifyCommunityMessage = onDocumentCreated(
  "chats/{chatId}/messages/{messageId}",
  async (event) => {
    const snap = event.data;
    if (!snap) return;
    const { chatId, messageId } = event.params;
    const msg = snap.data() || {};
    if (msg.deleted === true) return;

    const senderId = typeof msg.senderId === "string" ? msg.senderId : "";
    const senderName =
      typeof msg.senderName === "string" && msg.senderName.trim()
        ? msg.senderName.trim().slice(0, 40)
        : "Student";
    const text = typeof msg.text === "string" ? msg.text.replace(/\s+/g, " ").trim() : "";
    if (!senderId || !text) return;
    const preview = text.length > PREVIEW_MAX ? text.slice(0, PREVIEW_MAX - 3) + "..." : text;

    const logRef = db.collection("notification_logs").doc(`msg_${messageId}`);
    const throttleRef = db.collection("notification_logs").doc(`chat_${chatId}`);

    // Transaction: a message is pushed at most once (safe against Firestore retries),
    // and pushes for a chat are throttled.
    const shouldSend = await db.runTransaction(async (tx) => {
      const logDoc = await tx.get(logRef);
      if (logDoc.exists) return false;
      const throttleDoc = await tx.get(throttleRef);
      const now = Date.now();
      const last = throttleDoc.exists ? throttleDoc.get("lastSentAt") || 0 : 0;
      if (now - last < THROTTLE_MS) {
        tx.set(logRef, { status: "throttled", createdAt: now });
        return false;
      }
      tx.set(logRef, { status: "sent", createdAt: now });
      tx.set(throttleRef, { lastSentAt: now }, { merge: true });
      return true;
    });
    if (!shouldSend) return;

    try {
      await admin.messaging().send({
        topic: COMMUNITY_TOPIC,
        // Data-only message: the app builds the notification itself, so it works
        // in the background and when closed, and the sender can skip their own message.
        data: {
          type: "community",
          channel: "community",
          chatId,
          messageId,
          senderId,
          title: senderName,
          body: preview,
        },
        android: { priority: "high", ttl: 60 * 60 * 1000 },
      });
    } catch (e) {
      // Do not rethrow: that would make Firestore retry and loop.
      logger.error("Community push failed", { chatId, messageId, error: String(e.message || e) });
      await logRef.set({ status: "failed", error: String(e.message || e).slice(0, 200) }, { merge: true });
    }
  }
);
