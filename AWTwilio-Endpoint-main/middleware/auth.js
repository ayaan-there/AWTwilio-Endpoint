/**
 * middleware/auth.js
 * Verifies the JWT access token sent as "Authorization: Bearer <token>".
 * Attaches { userId, email } to req.user on success.
 */
const jwt = require('jsonwebtoken');

module.exports = function requireAuth(req, res, next) {
    const header = req.headers['authorization'] || '';
    const token  = header.startsWith('Bearer ') ? header.slice(7) : null;

    if (!token) {
        return res.status(401).json({ error: 'Missing access token' });
    }

    try {
        const payload = jwt.verify(token, process.env.JWT_SECRET);
        req.user = { userId: payload.sub, email: payload.email };
        next();
    } catch (err) {
        const msg = err.name === 'TokenExpiredError' ? 'Access token expired' : 'Invalid access token';
        return res.status(401).json({ error: msg });
    }
};
