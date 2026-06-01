/**
 * routes/auth.js
 * All authentication endpoints for AirWhisper.
 *
 * POST /auth/register          — create account, send verification OTP
 * POST /auth/verify-email      — verify OTP, activate account, return tokens
 * POST /auth/login             — email + password login, return tokens
 * POST /auth/forgot-password   — send password-reset OTP
 * POST /auth/verify-reset      — verify reset OTP (no password change yet)
 * POST /auth/reset-password    — change password after OTP verified
 * POST /auth/refresh-token     — exchange refresh token for new access token
 * POST /auth/logout            — invalidate refresh token
 */
const router  = require('express').Router();
const bcrypt  = require('bcryptjs');
const crypto  = require('crypto');
const https   = require('https');
const jwt     = require('jsonwebtoken');
const User    = require('../models/User');
const requireAuth = require('../middleware/auth');
const {
    createOTP,
    verifyOTP,
    checkVerificationResendLimit,
    deleteOTPKeysForEmail,
} = require('../services/otpService');
const { sendVerificationEmail, sendPasswordResetEmail } = require('../services/emailService');

// ── Token helpers ──────────────────────────────────────────────────────────

function signAccessToken(user) {
    return jwt.sign(
        { sub: user._id.toString(), email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: '15m' }
    );
}

function signRefreshToken(user) {
    return jwt.sign(
        { sub: user._id.toString() },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: '30d' }
    );
}

async function saveSessionAndRespond(user, res) {
    const accessToken  = signAccessToken(user);
    const refreshToken = signRefreshToken(user);

    user.refreshToken = await bcrypt.hash(refreshToken, 10);
    await user.save();

    return res.json({
        accessToken,
        refreshToken,
        user: { id: user._id, name: user.name, email: user.email },
    });
}

function normalizeEmail(email) {
    return typeof email === 'string' ? email.trim().toLowerCase() : '';
}

function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function makeDummyPasswordHash() {
    return bcrypt.hash(crypto.randomBytes(32).toString('hex'), 10);
}

// ── POST /auth/register ────────────────────────────────────────────────────
router.post('/register', async (req, res) => {
    const { name, email, password } = req.body;
    const normalizedEmail = normalizeEmail(email);

    if (!name || !normalizedEmail || !password) {
        return res.status(400).json({ error: 'name, email and password are required' });
    }
    if (!isValidEmail(normalizedEmail)) {
        return res.status(400).json({ error: 'A valid email is required' });
    }
    if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    try {
        const existing = await User.findOne({ email: normalizedEmail });
        if (existing) {
            return res.status(409).json({ error: 'An account with this email already exists' });
        }

        const passwordHash = await bcrypt.hash(password, 12);
        const user = await User.create({
            name: name.trim(),
            email: normalizedEmail,
            passwordHash,
        });

        const code = await createOTP('verify', normalizedEmail);
        try {
            await sendVerificationEmail(normalizedEmail, code);
        } catch (emailErr) {
            await User.deleteOne({ _id: user._id, verified: false });
            try {
                await deleteOTPKeysForEmail(normalizedEmail);
            } catch (redisErr) {
                console.error('[auth/register] OTP cleanup failed', redisErr);
            }
            console.error('[auth/register] verification email failed', emailErr);
            return res.status(502).json({ error: 'Could not send verification email. Please try again later.' });
        }

        res.status(201).json({ message: 'Account created — check your email for the verification code' });
    } catch (err) {
        console.error('[auth/register]', err);
        res.status(500).json({ error: 'Registration failed' });
    }
});

// -- POST /auth/resend-verification ----------------------------------------
router.post('/resend-verification', async (req, res) => {
    const email = normalizeEmail(req.body?.email);

    if (!email || !isValidEmail(email)) {
        return res.status(400).json({ error: 'A valid email is required.' });
    }

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ error: 'No account found for this email.' });
        }
        if (user.verified) {
            return res.status(409).json({ error: 'Email already verified. Please sign in.' });
        }

        const limit = await checkVerificationResendLimit(email);
        if (!limit.allowed) {
            return res.status(429).json({
                error: 'Too many verification code requests. Try again later.',
                retryAfterSeconds: limit.retryAfterSeconds,
            });
        }

        const code = await createOTP('verify', email);
        try {
            await sendVerificationEmail(email, code);
        } catch (emailErr) {
            console.error('[auth/resend-verification] email failed', emailErr);
            return res.status(502).json({ error: 'Could not send verification email. Please try again later.' });
        }

        res.json({ message: 'Verification code sent.' });
    } catch (err) {
        console.error('[auth/resend-verification]', err);
        res.status(500).json({ error: 'Could not resend verification code' });
    }
});

// ── POST /auth/verify-email ────────────────────────────────────────────────
router.post('/verify-email', async (req, res) => {
    const { email, code } = req.body;
    const normalizedEmail = normalizeEmail(email);
    if (!normalizedEmail || !code) {
        return res.status(400).json({ error: 'email and code are required' });
    }

    try {
        const ok = await verifyOTP('verify', normalizedEmail, code);
        if (!ok) {
            return res.status(400).json({ error: 'Invalid or expired verification code' });
        }

        const user = await User.findOneAndUpdate(
            { email: normalizedEmail },
            { verified: true },
            { new: true }
        );
        if (!user) return res.status(404).json({ error: 'User not found' });

        const accessToken  = signAccessToken(user);
        const refreshToken = signRefreshToken(user);

        // Store hashed refresh token
        user.refreshToken = await bcrypt.hash(refreshToken, 10);
        await user.save();

        res.json({
            accessToken,
            refreshToken,
            user: { id: user._id, name: user.name, email: user.email },
        });
    } catch (err) {
        console.error('[auth/verify-email]', err);
        res.status(500).json({ error: 'Verification failed' });
    }
});

// ── POST /auth/login ───────────────────────────────────────────────────────
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const normalizedEmail = normalizeEmail(email);
    if (!normalizedEmail || !password) {
        return res.status(400).json({ error: 'email and password are required' });
    }

    try {
        const user = await User.findOne({ email: normalizedEmail });
        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const passwordOk = await bcrypt.compare(password, user.passwordHash);
        if (!passwordOk) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        // Note: We no longer enforce email verification to login or send OTPs automatically here.

        const accessToken  = signAccessToken(user);
        const refreshToken = signRefreshToken(user);

        user.refreshToken = await bcrypt.hash(refreshToken, 10);
        await user.save();

        res.json({
            accessToken,
            refreshToken,
            user: { id: user._id, name: user.name, email: user.email },
        });
    } catch (err) {
        console.error('[auth/login]', err);
        res.status(500).json({ error: 'Login failed' });
    }
});

// ── POST /auth/forgot-password ─────────────────────────────────────────────
router.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    const normalizedEmail = normalizeEmail(email);
    if (!normalizedEmail) return res.status(400).json({ error: 'email is required' });

    try {
        const user = await User.findOne({ email: normalizedEmail });
        // Always respond 200 to prevent email enumeration
        if (user) {
            const code = await createOTP('reset', normalizedEmail);
            await sendPasswordResetEmail(normalizedEmail, code);
        }
        res.json({ message: 'If that email is registered, a reset code has been sent' });
    } catch (err) {
        console.error('[auth/forgot-password]', err);
        res.status(500).json({ error: 'Failed to send reset code' });
    }
});

// ── POST /auth/verify-reset ────────────────────────────────────────────────
// Verifies the reset OTP without changing the password.
// Returns a short-lived resetToken the client must include in /reset-password.
router.post('/verify-reset', async (req, res) => {
    const { email, code } = req.body;
    const normalizedEmail = normalizeEmail(email);
    if (!normalizedEmail || !code) {
        return res.status(400).json({ error: 'email and code are required' });
    }

    try {
        const ok = await verifyOTP('reset', normalizedEmail, code);
        if (!ok) {
            return res.status(400).json({ error: 'Invalid or expired reset code' });
        }

        // Issue a short-lived token so the client can call /reset-password
        const resetToken = jwt.sign(
            { sub: normalizedEmail, purpose: 'reset' },
            process.env.JWT_SECRET,
            { expiresIn: '10m' }
        );

        res.json({ resetToken });
    } catch (err) {
        console.error('[auth/verify-reset]', err);
        res.status(500).json({ error: 'Verification failed' });
    }
});

// ── POST /auth/reset-password ──────────────────────────────────────────────
router.post('/reset-password', async (req, res) => {
    const { resetToken, newPassword } = req.body;
    if (!resetToken || !newPassword) {
        return res.status(400).json({ error: 'resetToken and newPassword are required' });
    }
    if (newPassword.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    try {
        const payload = jwt.verify(resetToken, process.env.JWT_SECRET);
        if (payload.purpose !== 'reset') {
            return res.status(400).json({ error: 'Invalid reset token' });
        }

        const user = await User.findOne({ email: payload.sub });
        if (!user) return res.status(404).json({ error: 'User not found' });

        user.passwordHash = await bcrypt.hash(newPassword, 12);
        user.refreshToken = null; // invalidate all existing sessions
        await user.save();

        res.json({ message: 'Password updated — please log in again' });
    } catch (err) {
        if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
            return res.status(400).json({ error: 'Reset token invalid or expired' });
        }
        console.error('[auth/reset-password]', err);
        res.status(500).json({ error: 'Password reset failed' });
    }
});

// ── POST /auth/refresh-token ───────────────────────────────────────────────
router.post('/refresh-token', async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) {
        return res.status(400).json({ error: 'refreshToken is required' });
    }

    try {
        const payload = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
        const user    = await User.findById(payload.sub);

        if (!user || !user.refreshToken) {
            return res.status(401).json({ error: 'Session not found — please log in again' });
        }

        const tokenMatches = await bcrypt.compare(refreshToken, user.refreshToken);
        if (!tokenMatches) {
            return res.status(401).json({ error: 'Refresh token reuse detected — please log in again' });
        }

        const newAccessToken  = signAccessToken(user);
        const newRefreshToken = signRefreshToken(user);

        user.refreshToken = await bcrypt.hash(newRefreshToken, 10);
        await user.save();

        res.json({ accessToken: newAccessToken, refreshToken: newRefreshToken });
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Session expired — please log in again' });
        }
        console.error('[auth/refresh-token]', err);
        res.status(401).json({ error: 'Invalid refresh token' });
    }
});

// -- Apple Sign-In helpers --------------------------------------------------

const APPLE_ISSUER = 'https://appleid.apple.com';
const APPLE_JWKS_URL = 'https://appleid.apple.com/auth/keys';
const APPLE_JWKS_CACHE_MS = 60 * 60 * 1000;
let appleJWKSCache = { fetchedAt: 0, keys: [] };

function httpsJSON(url) {
    return new Promise((resolve, reject) => {
        https.get(url, (r) => {
            let data = '';
            r.on('data', chunk => data += chunk);
            r.on('end', () => {
                try {
                    resolve({ status: r.statusCode, body: JSON.parse(data) });
                } catch (e) {
                    reject(e);
                }
            });
        }).on('error', reject);
    });
}

async function fetchAppleJWKS(force = false) {
    const cacheFresh = appleJWKSCache.keys.length > 0 &&
        Date.now() - appleJWKSCache.fetchedAt < APPLE_JWKS_CACHE_MS;

    if (!force && cacheFresh) {
        return appleJWKSCache.keys;
    }

    const response = await httpsJSON(APPLE_JWKS_URL);
    if (response.status !== 200 || !Array.isArray(response.body.keys)) {
        throw new Error('Unable to fetch Apple public keys');
    }

    appleJWKSCache = { fetchedAt: Date.now(), keys: response.body.keys };
    return appleJWKSCache.keys;
}

async function applePublicKeyForToken(identityToken) {
    const decoded = jwt.decode(identityToken, { complete: true });
    const kid = decoded?.header?.kid;
    if (!kid) {
        throw new Error('Apple token missing key identifier');
    }

    let keys = await fetchAppleJWKS();
    let jwk = keys.find(key => key.kid === kid);

    if (!jwk) {
        keys = await fetchAppleJWKS(true);
        jwk = keys.find(key => key.kid === kid);
    }

    if (!jwk) {
        throw new Error('Apple signing key not found');
    }

    return crypto.createPublicKey({ key: jwk, format: 'jwk' });
}

async function verifyAppleIdentityToken(identityToken) {
    if (!process.env.APPLE_CLIENT_ID) {
        throw new Error('APPLE_CLIENT_ID is not configured');
    }

    const publicKey = await applePublicKeyForToken(identityToken);
    return jwt.verify(identityToken, publicKey, {
        algorithms: ['RS256'],
        audience: process.env.APPLE_CLIENT_ID,
        issuer: APPLE_ISSUER,
    });
}

function isAppleEmailVerified(claims) {
    return claims.email_verified === true || claims.email_verified === 'true';
}

// -- POST /auth/apple -------------------------------------------------------
router.post('/apple', async (req, res) => {
    const { identityToken, authorizationCode, fullName } = req.body;
    if (!identityToken || !authorizationCode) {
        return res.status(400).json({ error: 'identityToken and authorizationCode are required' });
    }

    try {
        const claims = await verifyAppleIdentityToken(identityToken);
        const appleUserIdentifier = claims.sub;
        const tokenEmail = normalizeEmail(claims.email);
        const tokenEmailVerified = isAppleEmailVerified(claims);
        const providedName = typeof fullName === 'string' ? fullName.trim() : '';

        if (!appleUserIdentifier) {
            return res.status(401).json({ error: 'Invalid Apple token' });
        }

        let user = await User.findOne({ appleUserIdentifier });
        if (user) {
            if (!user.verified) user.verified = true;
            return saveSessionAndRespond(user, res);
        }

        if (!tokenEmail) {
            return res.status(400).json({ error: 'Please share your email with Apple Sign-In to create an account.' });
        }

        user = await User.findOne({ email: tokenEmail });
        if (user) {
            if (!tokenEmailVerified) {
                return res.status(401).json({ error: 'Apple email is not verified' });
            }
            if (user.appleUserIdentifier && user.appleUserIdentifier !== appleUserIdentifier) {
                return res.status(409).json({ error: 'This email is already linked to another Apple account' });
            }
            user.appleUserIdentifier = appleUserIdentifier;
            user.verified = true;
            if (providedName && (!user.name || user.name === 'Apple User')) {
                user.name = providedName;
            }
            return saveSessionAndRespond(user, res);
        }

        const passwordHash = await makeDummyPasswordHash();
        user = await User.create({
            name: providedName || 'Apple User',
            email: tokenEmail,
            passwordHash,
            verified: true,
            appleUserIdentifier,
        });

        return saveSessionAndRespond(user, res);
    } catch (err) {
        console.error('[auth/apple]', err);
        res.status(401).json({ error: 'Apple sign-in failed' });
    }
});

// ── POST /auth/google ──────────────────────────────────────────────────────
// Accepts a Google ID token from the iOS app, verifies it with Google's
// tokeninfo endpoint, upserts the user in MongoDB, and returns the same
// { accessToken, refreshToken, user } shape as /auth/login.

router.post('/google', async (req, res) => {
    const { idToken } = req.body;
    if (!idToken) return res.status(400).json({ error: 'idToken is required' });

    try {
        // Verify with Google
        const googleRes = await new Promise((resolve, reject) => {
            https.get(
                `https://oauth2.googleapis.com/tokeninfo?id_token=${idToken}`,
                (r) => {
                    let data = '';
                    r.on('data', chunk => data += chunk);
                    r.on('end', () => {
                        try { resolve({ status: r.statusCode, body: JSON.parse(data) }); }
                        catch (e) { reject(e); }
                    });
                }
            ).on('error', reject);
        });

        if (googleRes.status !== 200 || googleRes.body.aud !== process.env.GOOGLE_CLIENT_ID) {
            return res.status(401).json({ error: 'Invalid Google token' });
        }

        const { email, name } = googleRes.body;
        if (!email) return res.status(401).json({ error: 'No email in Google token' });

        // Upsert: Google users have no password; use a random bcrypt hash as placeholder
        let user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            const dummyHash = await makeDummyPasswordHash();
            user = await User.create({
                name:         name || 'Google User',
                email:        email.toLowerCase(),
                passwordHash: dummyHash,
                verified:     true,
            });
        }

        const accessToken  = signAccessToken(user);
        const refreshToken = signRefreshToken(user);

        user.refreshToken = await bcrypt.hash(refreshToken, 10);
        await user.save();

        res.json({
            accessToken,
            refreshToken,
            user: { id: user._id, name: user.name, email: user.email },
        });
    } catch (err) {
        console.error('[auth/google]', err);
        res.status(500).json({ error: 'Google sign-in failed' });
    }
});

// ── POST /auth/logout ──────────────────────────────────────────────────────
router.post('/logout', async (req, res) => {
    const { refreshToken } = req.body;

    try {
        if (refreshToken) {
            const payload = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
            const user    = await User.findById(payload.sub);
            if (user) {
                user.refreshToken = null;
                await user.save();
            }
        }
    } catch (_) {
        // Ignore invalid token errors on logout — always succeed
    }

    res.json({ message: 'Logged out' });
});

// -- DELETE /auth/account ---------------------------------------------------
router.delete('/account', requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        if (user.email) {
            try {
                await deleteOTPKeysForEmail(user.email);
            } catch (redisErr) {
                console.error('[auth/account] OTP cleanup failed', redisErr);
            }
        }

        // Apple token revocation can be added here if appleRefreshToken is stored.
        await User.deleteOne({ _id: user._id });

        res.json({ message: 'Account deleted.' });
    } catch (err) {
        console.error('[auth/account]', err);
        res.status(500).json({ error: 'Account deletion failed' });
    }
});

module.exports = router;
