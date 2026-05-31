/**
 * models/User.js
 * Mongoose schema for AirWhisper registered users.
 */
const { Schema, model } = require('mongoose');

const userSchema = new Schema({
    name:         { type: String, required: true, trim: true },
    email:        { type: String, required: true, unique: true, lowercase: true, trim: true },
    passwordHash: { type: String, required: true },
    verified:     { type: Boolean, default: false },
    refreshToken: { type: String, default: null },   // stored hashed
}, { timestamps: true });

module.exports = model('User', userSchema);
