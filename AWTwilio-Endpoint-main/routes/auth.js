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
const jwt     = require('jsonwebtoken');
const User    = require('../models/User');
const { createOTP, verifyOTP } = require('../services/otpService');
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

// ── POST /auth/register ────────────────────────────────────────────────────
router.post('/register', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ error: 'name, email and password are required' });
    }
    if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    try {
        const existing = await User.findOne({ email: email.toLowerCase() });
        if (existing) {
            return res.status(409).json({ error: 'An account with this email already exists' });
        }

        const passwordHash = await bcrypt.hash(password, 12);
        const user = await User.create({ name, email, passwordHash });

        const code = await createOTP('verify', email);
        await sendVerificationEmail(email, code);

        res.status(201).json({ message: 'Account created — check your email for the verification code' });
    } catch (err) {
        console.error('[auth/register]', err);
        res.status(500).json({ error: 'Registration failed' });
    }
});

// ── POST /auth/verify-email ────────────────────────────────────────────────
router.post('/verify-email', async (req, res) => {
    const { email, code } = req.body;
    if (!email || !code) {
        return res.status(400).json({ error: 'email and code are required' });
    }

    try {
        const ok = await verifyOTP('verify', email, code);
        if (!ok) {
            return res.status(400).json({ error: 'Invalid or expired verification code' });
        }

        const user = await User.findOneAndUpdate(
            { email: email.toLowerCase() },
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
    if (!email || !password) {
        return res.status(400).json({ error: 'email and password are required' });
    }

    try {
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const passwordOk = await bcrypt.compare(password, user.passwordHash);
        if (!passwordOk) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        if (!user.verified) {
            // Re-send verification OTP so user can complete registration
            const code = await createOTP('verify', email);
            await sendVerificationEmail(email, code);
            return res.status(403).json({ error: 'Email not verified — a new code has been sent' });
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
        console.error('[auth/login]', err);
        res.status(500).json({ error: 'Login failed' });
    }
});

// ── POST /auth/forgot-password ─────────────────────────────────────────────
router.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'email is required' });

    try {
        const user = await User.findOne({ email: email.toLowerCase() });
        // Always respond 200 to prevent email enumeration
        if (user) {
            const code = await createOTP('reset', email);
            await sendPasswordResetEmail(email, code);
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
    if (!email || !code) {
        return res.status(400).json({ error: 'email and code are required' });
    }

    try {
        const ok = await verifyOTP('reset', email, code);
        if (!ok) {
            return res.status(400).json({ error: 'Invalid or expired reset code' });
        }

        // Issue a short-lived token so the client can call /reset-password
        const resetToken = jwt.sign(
            { sub: email.toLowerCase(), purpose: 'reset' },
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

// ── POST /auth/google ──────────────────────────────────────────────────────
// Accepts a Google ID token from the iOS app, verifies it with Google's
// tokeninfo endpoint, upserts the user in MongoDB, and returns the same
// { accessToken, refreshToken, user } shape as /auth/login.
const https = require('https');

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
            const dummyHash = await bcrypt.hash(require('crypto').randomBytes(32).toString('hex'), 10);
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

module.exports = router;
