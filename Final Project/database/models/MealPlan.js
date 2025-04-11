const mongoose = require('mongoose');

const mealPlanSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  week: { type: String }, // e.g., '2025-W15'
  days: [{
    day: String,
    recipes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Recipe' }]
  }]
}, { timestamps: true });

module.exports = mongoose.model('MealPlan', mealPlanSchema);
