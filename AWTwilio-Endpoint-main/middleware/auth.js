/**
 * middleware/auth.js
 * Verifies the JWT access token sent as "Authorization: Bearer <token>".
 * Also confirms the user document still exists in the database.
 * Attaches { userId, email } to req.user on success.
 */
const jwt = require('jsonwebtoken');
const User = require('../models/User');

module.exports = async function requireAuth(req, res, next) {
    try {
        const header = req.headers['authorization'] || '';
        const token  = header.startsWith('Bearer ') ? header.slice(7) : null;

        if (!token) {
            return res.status(401).json({ error: 'Missing access token' });
        }

        const payload = jwt.verify(token, process.env.JWT_SECRET);
        req.user = { userId: payload.sub, email: payload.email };

        const user = await User.findById(payload.sub).select('_id');
        if (!user) {
            return res.status(401).json({ error: 'Account no longer exists' });
        }

        next();
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Access token expired' });
        }
        if (err.name === 'JsonWebTokenError') {
            return res.status(401).json({ error: 'Invalid access token' });
        }
        return res.status(500).json({ error: 'Authentication failed' });
    }
};
