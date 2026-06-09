/**
 * services/emailService.js
 * Sends transactional emails via the Resend API.
 */
const { Resend } = require('resend');

const resend = new Resend(process.env.RESEND_API_KEY);
const FROM   = process.env.EMAIL_FROM || 'AirWhisper <noreply@airwhisper.app>';

/**
 * Sends the 6-digit email-verification OTP to the new user.
 */
async function sendVerificationEmail(toEmail, code) {
    await resend.emails.send({
        from: FROM,
        to:   toEmail,
        subject: 'Your AirWhisper verification code',
        html: `
            <div style="font-family:sans-serif;max-width:480px;margin:auto">
                <h2 style="color:#0a0a0a">Verify your email</h2>
                <p>Enter this code in the AirWhisper app to confirm your email address:</p>
                <div style="font-size:36px;font-weight:700;letter-spacing:8px;color:#0060f5;margin:24px 0">
                    ${code}
                </div>
                <p style="color:#666;font-size:13px">This code expires in 10 minutes. If you didn't create an account, you can ignore this email.</p>
            </div>
        `,
    });
}

/**
 * Sends the password-reset OTP.
 */
async function sendPasswordResetEmail(toEmail, code) {
    await resend.emails.send({
        from: FROM,
        to:   toEmail,
        subject: 'Reset your AirWhisper password',
        html: `
            <div style="font-family:sans-serif;max-width:480px;margin:auto">
                <h2 style="color:#0a0a0a">Reset your password</h2>
                <p>Enter this code in the AirWhisper app to reset your password:</p>
                <div style="font-size:36px;font-weight:700;letter-spacing:8px;color:#0060f5;margin:24px 0">
                    ${code}
                </div>
                <p style="color:#666;font-size:13px">This code expires in 10 minutes. If you didn't request a password reset, you can ignore this email.</p>
            </div>
        `,
    });
}

module.exports = { sendVerificationEmail, sendPasswordResetEmail };
