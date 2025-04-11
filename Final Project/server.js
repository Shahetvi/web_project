require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const connectDB = require('./database/connect');
const User = require('./database/models/User');
const Recipe = require('./database/models/Recipe');
const Review = require('./database/models/Review');
const MealPlan = require('./database/models/MealPlan');

const app = express();
connectDB();
app.use(express.json());

// Middleware for authentication
const authenticateToken = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Access Denied. No token provided.' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(400).json({ message: 'Invalid token.' });
  }
};

// Role check middleware
const checkRole = (roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) {
    return res.status(403).json({ message: 'Forbidden: insufficient rights' });
  }
  next();
};

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password, role } = req.body;
  try {
    // Check if the email already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'User with this email already exists.' });

    // Hash the password before saving it to DB
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user
    const user = new User({ username, email, password: hashedPassword, role });
    await user.save();

    // Generate a JWT token for the user
    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET);
    res.json({ token });
  } catch (err) {
    console.error('Error creating user:', err);
    res.status(500).json({ message: 'Server error : ' + err });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET);
    res.json({ token });
  } catch (err) {
    console.error('Error creating user:', err);
    res.status(500).json({ message: 'Server error : ' + err });
  }
});

// Recipe CRUD Routes
app.post('/api/recipes', authenticateToken, async (req, res) => {
  try {
    const recipe = new Recipe({ ...req.body, author: req.user.id });
    await recipe.save();
    res.status(201).json(recipe);
  } catch (err) {
    console.error('Error creating user:', err);
    res.status(500).json({ message: 'Server error : ' + err });
  }
});

app.get('/api/recipes', async (req, res) => {
  try {
    const recipes = await Recipe.find();
    res.json(recipes);
  } catch (err) {
    console.error('Error creating user:', err);
    res.status(500).json({ message: 'Server error : ' + err });
  }
});

app.put('/api/recipes/:id', authenticateToken, async (req, res) => {
  try {
    const updated = await Recipe.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(updated);
  } catch (err) {
    res.status(400).json({ message: 'Error updating recipe' });
  }
});

app.delete('/api/recipes/:id', authenticateToken, async (req, res) => {
  try {
    await Recipe.findByIdAndDelete(req.params.id);
    res.json({ message: 'Recipe deleted' });
  } catch (err) {
    res.status(400).json({ message: 'Error deleting recipe' });
  }
});

// Review Routes
app.post('/api/reviews', authenticateToken, async (req, res) => {
  try {
    const review = new Review({ ...req.body, user: req.user.id });
    await review.save();
    res.status(201).json(review);
  } catch (err) {
    res.status(400).json({ message: 'Error creating review' });
  }
});

app.get('/api/reviews/:recipeId', async (req, res) => {
  try {
    const reviews = await Review.find({ recipe: req.params.recipeId }).populate('user', 'username');
    res.json(reviews);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching reviews' });
  }
});

// Meal Plan Routes
app.post('/api/mealplans', authenticateToken, async (req, res) => {
  try {
    const mealPlan = new MealPlan({ ...req.body, user: req.user.id });
    await mealPlan.save();
    res.status(201).json(mealPlan);
  } catch (err) {
    res.status(400).json({ message: 'Error creating meal plan' });
  }
});

app.get('/api/mealplans', authenticateToken, async (req, res) => {
  try {
    const mealPlans = await MealPlan.find({ user: req.user.id }).populate('days.recipes');
    res.json(mealPlans);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching meal plans' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
