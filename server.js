// =========================================================
// INIT
// =========================================================
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const nodemailer = require("nodemailer");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

// =========================================================
// ADMIN SIMPLE PASSWORD
// =========================================================
const ADMIN_KEY = process.env.ADMIN_KEY || "liki@2921";

function adminLock(req, res, next) {
  if (req.query.key !== ADMIN_KEY) {
    return res.status(403).send("Forbidden: Invalid admin key");
  }
  next();
}

// =========================================================
// JSON FALLBACK STORAGE
// =========================================================
const DATA_DIR = path.join(__dirname, "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");
const TX_FILE = path.join(DATA_DIR, "txids.json");

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, JSON.stringify({}), "utf8");
if (!fs.existsSync(TX_FILE)) fs.writeFileSync(TX_FILE, JSON.stringify([]), "utf8");

function loadUsers() { return JSON.parse(fs.readFileSync(USERS_FILE, "utf8") || "{}"); }
function saveUsers(u) { fs.writeFileSync(USERS_FILE, JSON.stringify(u, null, 2), "utf8"); }

function loadTx() { return JSON.parse(fs.readFileSync(TX_FILE, "utf8") || "[]"); }
function saveTx(t) { fs.writeFileSync(TX_FILE, JSON.stringify(t, null, 2), "utf8"); }

// =========================================================
// MONGODB CONFIG
// =========================================================
const { MongoClient } = require("mongodb");
const MONGODB_URI = process.env.MONGODB_URI;
const MONGODB_DB = process.env.MONGODB_DB || "mines_app";
const USERS_COLL = process.env.USERS_COLL || "users";

let db = null;

async function connectMongo() {
  if (!MONGODB_URI) return;
  try {
    const client = new MongoClient(MONGODB_URI);
    await client.connect();
    db = client.db(MONGODB_DB);
    console.log("Connected to MongoDB Atlas");
  } catch (e) {
    console.error("Mongo Error:", e);
  }
}

// =========================================================
// AUTH HELPERS
// =========================================================
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const JWT_SECRET = process.env.JWT_SECRET || "please_set_secret";

function createToken(username) {
  return jwt.sign({ user: username }, JWT_SECRET, { expiresIn: "7d" });
}

function authMiddleware(req, res, next) {
  const h = req.headers.authorization || req.headers.Authorization;
  if (!h) return next();
  const [scheme, token] = h.split(" ");
  if (scheme !== "Bearer") return next();
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.authUser = decoded.user;
  } catch {}
  next();
}
app.use(authMiddleware);

// =========================================================
// EMAIL: RESEND SMTP (REPLACES GMAIL)
// =========================================================
const transporter = nodemailer.createTransport({
  host: "smtp.resend.com",
  port: 587,
  secure: false,
  auth: {
    user: "resend",
    pass: process.env.RESEND_API_KEY,
  },
});

async function sendEmail(to, subject, text) {
  try {
    await transporter.sendMail({
      from: process.env.ADMIN_EMAIL,
      to,
      subject,
      text,
    });
    console.log("EMAIL SENT →", to);
  } catch (err) {
    console.error("EMAIL ERROR →", err);
  }
}

// =========================================================
// STORAGE LAYER
// =========================================================

async function getUserFromStore(username) {
  if (db) return await db.collection(USERS_COLL).findOne({ _id: username });
  return loadUsers()[username] || null;
}

async function ensureUserInStore(username) {
  if (db) {
    await db.collection(USERS_COLL).updateOne(
      { _id: username },
      { $setOnInsert: { credits: 0, redemptions: [] } },
      { upsert: true }
    );
    return await db.collection(USERS_COLL).findOne({ _id: username });
  }
  const users = loadUsers();
  if (!users[username]) users[username] = { credits: 0, redemptions: [] };
  saveUsers(users);
  return users[username];
}

async function creditUserInStore(username, amount) {
  if (db) {
    const res = await db.collection(USERS_COLL).findOneAndUpdate(
      { _id: username },
      { $inc: { credits: amount } },
      { returnDocument: "after" }
    );
    return res.value.credits;
  }
  const users = loadUsers();
  users[username].credits += amount;
  saveUsers(users);
  return users[username].credits;
}

async function debitUserInStore(username, amount) {
  if (db) {
    const u = await db.collection(USERS_COLL).findOne({ _id: username });
    if (!u) throw new Error("user not found");
    if (u.credits < amount) throw new Error("insufficient credits");

    const res = await db.collection(USERS_COLL).findOneAndUpdate(
      { _id: username },
      { $inc: { credits: -amount } },
      { returnDocument: "after" }
    );

    return res.value.credits;
  }

  const users = loadUsers();
  if (!users[username]) throw new Error("user not found");
  if (users[username].credits < amount) throw new Error("insufficient credits");

  users[username].credits -= amount;
  saveUsers(users);
  return users[username].credits;
}

async function listTxsFromStore() {
  if (db) return await db.collection("txids").find({}).toArray();
  return loadTx();
}

async function createTxInStore(record) {
  if (db) {
    await db.collection("txids").insertOne(record);
    return record;
  }
  const txs = loadTx();
  txs.push(record);
  saveTx(txs);
  return record;
}

async function confirmTxInStore(id, amount) {
  if (db) {
    const col = db.collection("txids");
    const tx = await col.findOne({ id });
    if (!tx) throw new Error("txid not found");
    if (tx.status === "confirmed") return tx;

    await col.updateOne(
      { id },
      { $set: { status: "confirmed", confirmedAt: new Date().toISOString() } }
    );

    await creditUserInStore(tx.user, amount);
    return await col.findOne({ id });
  }

  const txs = loadTx();
  const tx = txs.find((t) => t.id === id);
  if (!tx) throw new Error("txid not found");
  if (tx.status === "confirmed") return tx;

  tx.status = "confirmed";
  tx.confirmedAt = new Date().toISOString();
  saveTx(txs);

  const users = loadUsers();
  users[tx.user].credits += amount;
  saveUsers(users);

  return tx;
}

// =========================================================
// PUBLIC ROUTES
// =========================================================
app.get("/", (req, res) => res.json({ ok: true }));

// REGISTER
app.post("/api/register", async (req, res) => {
  try {
    const { user, password } = req.body;

    const existing = await getUserFromStore(user);
    if (existing) return res.status(400).json({ error: "user exists" });

    const hash = await bcrypt.hash(password, 10);

    if (db) {
      await db.collection(USERS_COLL).insertOne({
        _id: user,
        passwordHash: hash,
        credits: 0,
        redemptions: [],
      });
    } else {
      const users = loadUsers();
      users[user] = { passwordHash: hash, credits: 0, redemptions: [] };
      saveUsers(users);
    }

    res.json({ ok: true, token: createToken(user) });
  } catch (e) {
    res.status(500).json({ error: "failed" });
  }
});

// LOGIN
app.post("/api/login", async (req, res) => {
  const { user, password } = req.body;

  const u = await getUserFromStore(user);
  if (!u || !u.passwordHash) return res.status(400).json({ error: "invalid credentials" });

  const ok = await bcrypt.compare(password, u.passwordHash);
  if (!ok) return res.status(400).json({ error: "invalid credentials" });

  res.json({ ok: true, token: createToken(user), credits: u.credits });
});

// AUTH USER DATA
app.get("/api/me", async (req, res) => {
  if (!req.authUser) return res.status(401).json({ error: "not authenticated" });

  const user = await getUserFromStore(req.authUser);
  if (!user) return res.status(404).json({ error: "not found" });

  const { passwordHash, ...clean } = user;
  res.json({ ok: true, user: clean });
});

// DEBIT
app.post("/api/user/:user/debit", async (req, res) => {
  try {
    const credits = await debitUserInStore(req.params.user, req.body.amount);
    res.json({ ok: true, credits });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// CREDIT
app.post("/api/user/:user/credit", async (req, res) => {
  const credits = await creditUserInStore(req.params.user, req.body.amount);
  res.json({ ok: true, credits });
});

// SUBMIT TXID + EMAIL
app.post("/api/txid", async (req, res) => {
  const { user, txid } = req.body;

  await ensureUserInStore(user);

  const exists = (await listTxsFromStore()).some((t) => t.txid === txid);
  if (exists) return res.status(400).json({ error: "duplicate txid" });

  const record = {
    id: Date.now().toString(36) + Math.random().toString(36).slice(2, 8),
    user,
    txid,
    status: "pending",
    date: new Date().toISOString(),
  };

  await createTxInStore(record);

  sendEmail(
    process.env.ADMIN_EMAIL,
    "New TXID Submitted",
    `User: ${user}\nTXID: ${txid}\nID: ${record.id}`
  );

  res.json({ ok: true, id: record.id });
});

// =========================================================
// ADMIN ROUTES
// =========================================================
app.get("/api/admin/txids", adminLock, async (req, res) => {
  res.json({ ok: true, txs: await listTxsFromStore() });
});

// CONFIRM TXID + EMAIL
app.post("/api/admin/confirm", adminLock, async (req, res) => {
  try {
    const tx = await confirmTxInStore(req.body.id, 5);

    sendEmail(
      process.env.ADMIN_EMAIL,
      "TXID Confirmed",
      `TXID: ${tx.txid}\nUser: ${tx.user}\nCredits Added: 5`
    );

    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// =========================================================
// ADMIN PANEL STATIC
// =========================================================
app.use("/admin", adminLock, express.static(path.join(__dirname, "admin")));

// =========================================================
// START SERVER
// =========================================================
(async () => {
  await connectMongo();
  app.listen(PORT, () => {
    console.log(`Backend running: http://localhost:${PORT}`);
    console.log(`Admin login: /admin?key=${ADMIN_KEY}`);
  });
})();