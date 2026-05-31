require('dotenv').config();
const express = require('express');
const twilio = require('twilio');
const helmet = require('helmet');

const app = express();
app.use(helmet()); // Secure HTTP headers
app.use(express.json());

const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

// Middleware to check for a custom API Key from your iOS app
app.post('/send-sms', async (req, res) => {
    const { to, body } = req.body;

    try {
        const message = await client.messages.create({
            body: body,
            from: process.env.TWILIO_PHONE_NUMBER, // Your International Number
            to: to // E.164 format: e.g., +919876543210
        });
        res.status(200).json({ success: true, sid: message.sid });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));