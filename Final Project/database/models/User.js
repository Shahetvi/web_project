const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, required: true, unique: true, match: /.+\@.+\..+/ },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  dietaryPreferences: [String],
  favorites: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Recipe' }],
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);


