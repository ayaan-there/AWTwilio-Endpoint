/**
 * server.js — AirWhisper backend entry point (Phase 3)
 *
 * Required environment variables (set in .env or Render dashboard):
 *   MONGODB_URI          — MongoDB connection string (e.g. mongodb+srv://...)
 *   JWT_SECRET           — Long random string for signing access tokens
 *   JWT_REFRESH_SECRET   — Separate long random string for refresh tokens
 *   UPSTASH_REDIS_URL    — Redis URL from Upstash (redis://...)
 *   RESEND_API_KEY       — API key from resend.com
 *   EMAIL_FROM           — Sender address verified in Resend (e.g. noreply@yourdomain.com)
 *   TWILIO_ACCOUNT_SID   — Twilio Account SID
 *   TWILIO_AUTH_TOKEN    — Twilio Auth Token
 *   TWILIO_PHONE_NUMBER  — Twilio outbound phone number in E.164 format
 *   GOOGLE_CLIENT_ID     — iOS OAuth 2.0 client ID from Google Cloud Console
 *   PORT                 — (optional) defaults to 3000
 */

require('dotenv').config();
const express = require('express');
const helmet  = require('helmet');

const connectDB   = require('./db');
const authRoutes  = require('./routes/auth');
const smsRoutes   = require('./routes/sms');

const app = express();
app.use(helmet());
app.use(express.json());

// ── Database ───────────────────────────────────────────────────────────────
connectDB();

// ── Routes ─────────────────────────────────────────────────────────────────
app.use('/auth', authRoutes);
app.use('/',     smsRoutes);

// ── Health check ───────────────────────────────────────────────────────────
app.get('/health', (_req, res) => res.json({ ok: true }));

// ── Start ──────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`AirWhisper server running on port ${PORT}`));
