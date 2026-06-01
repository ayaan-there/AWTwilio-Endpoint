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
const RESEND_VERIFY_LIMIT = 3;
const RESEND_VERIFY_WINDOW_SECONDS = 15 * 60;

function normalizeEmail(email) {
    return email.trim().toLowerCase();
}

function generateCode() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

/**
 * Creates and stores a new OTP for the given purpose + email.
 * Returns the 6-digit code string.
 */
async function createOTP(purpose, email) {
    const code = generateCode();
    const key  = `otp:${purpose}:${normalizeEmail(email)}`;
    await redis.set(key, code, 'EX', OTP_TTL_SECONDS);
    return code;
}

/**
 * Verifies a submitted code. Returns true on match (and deletes the key),
 * false if wrong or expired.
 */
async function verifyOTP(purpose, email, code) {
    const key    = `otp:${purpose}:${normalizeEmail(email)}`;
    const stored = await redis.get(key);
    if (!stored || stored !== code) return false;
    await redis.del(key);
    return true;
}

async function checkVerificationResendLimit(email) {
    const normalized = normalizeEmail(email);
    const key = `otp:resend:verify:${normalized}`;
    const attempts = await redis.incr(key);

    if (attempts === 1) {
        await redis.expire(key, RESEND_VERIFY_WINDOW_SECONDS);
    }

    const ttl = await redis.ttl(key);
    const retryAfterSeconds = ttl > 0 ? ttl : RESEND_VERIFY_WINDOW_SECONDS;

    if (attempts > RESEND_VERIFY_LIMIT) {
        return { allowed: false, retryAfterSeconds };
    }

    return {
        allowed: true,
        remaining: Math.max(RESEND_VERIFY_LIMIT - attempts, 0),
        retryAfterSeconds,
    };
}

async function deleteOTPKeysForEmail(email) {
    const normalized = normalizeEmail(email);
    await redis.del(
        `otp:verify:${normalized}`,
        `otp:reset:${normalized}`,
        `otp:resend:verify:${normalized}`
    );
}

module.exports = {
    createOTP,
    verifyOTP,
    checkVerificationResendLimit,
    deleteOTPKeysForEmail,
};
