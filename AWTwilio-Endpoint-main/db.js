const mongoose = require('mongoose');

module.exports = async function connectDB() {
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('[DB] MongoDB connected');
    } catch (err) {
        console.error('[DB] Connection failed:', err.message);
        process.exit(1);
    }
};
