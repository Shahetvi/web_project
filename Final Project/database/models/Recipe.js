const mongoose = require('mongoose');

const ingredientSchema = new mongoose.Schema({
  name: String,
  quantity: Number,
  unit: String
}, { _id: false });

const recipeSchema = new mongoose.Schema({
  name: { type: String, required: true },
  ingredients: [ingredientSchema],
  instructions: { type: String, required: true },
  cuisine: String,
  mealType: String,
  nutrition: {
    calories: Number,
    fat: Number,
    carbs: Number,
    protein: Number
  },
  prepTime: Number,
  difficulty: { type: String, enum: ['easy', 'medium', 'hard'] },
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
}, { timestamps: true });

module.exports = mongoose.model('Recipe', recipeSchema);
