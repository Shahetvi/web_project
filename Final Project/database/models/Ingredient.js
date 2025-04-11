const mongoose = require('mongoose');

const ingredientSchema = new mongoose.Schema({
  name: { type: String, required: true },
  unit: { type: String },
  description: String
}, { timestamps: true });

module.exports = mongoose.model('Ingredient', ingredientSchema);
