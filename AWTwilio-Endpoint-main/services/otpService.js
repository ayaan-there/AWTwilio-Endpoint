/**
 * services/otpService.js
 * Manages 6-digit OTP codes via Upstash Redis.
 *
 * Key format: otp:<purpose>:<email>
 * TTL: 10 minutes
 * Purpose values: "verify" (email verification) | "reset" (password reset)
 */
const Redis = require('ioredis');

const redis = new Redis(process.env.UPSTASH_REDIS_URL);

const OTP_TTL_SECONDS = 600; // 10 minutes

function generateCode() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

/**
 * Creates and stores a new OTP for the given purpose + email.
 * Returns the 6-digit code string.
 */
async function createOTP(purpose, email) {
    const code = generateCode();
    const key  = `otp:${purpose}:${email.toLowerCase()}`;
    await redis.set(key, code, 'EX', OTP_TTL_SECONDS);
    return code;
}

/**
 * Verifies a submitted code. Returns true on match (and deletes the key),
 * false if wrong or expired.
 */
async function verifyOTP(purpose, email, code) {
    const key    = `otp:${purpose}:${email.toLowerCase()}`;
    const stored = await redis.get(key);
    if (!stored || stored !== code) return false;
    await redis.del(key);
    return true;
}

module.exports = { createOTP, verifyOTP };
