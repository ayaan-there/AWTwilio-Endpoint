/**
 * routes/sms.js
 * Protected SMS relay endpoint — requires a valid JWT access token.
 */
const router    = require('express').Router();
const twilio    = require('twilio');
const requireAuth = require('../middleware/auth');

const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

router.post('/send-sms', requireAuth, async (req, res) => {
    const { to, body } = req.body;

    if (!to || !body) {
        return res.status(400).json({ success: false, error: 'to and body are required' });
    }

    try {
        const message = await client.messages.create({
            body,
            from: process.env.TWILIO_PHONE_NUMBER,
            to,
        });
        res.status(200).json({ success: true, sid: message.sid });
    } catch (error) {
        console.error('[sms/send]', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

module.exports = router;
