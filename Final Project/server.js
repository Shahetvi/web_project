require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const connectDB = require('./database/connect');
const User = require('./database/models/User');
const Recipe = require('./database/models/Recipe');
const path = require('path');
const cookieParser = require('cookie-parser');

const app = express();
connectDB();

// Middlewares
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// JWT Middleware
const authenticateToken = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.redirect('/login');
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.clearCookie('token');
    res.redirect('/login');
  }
};

// EJS Routes
app.get('/', (req, res) => res.render('index'));
app.get('/register', (req, res) => res.render('register', { error: null }));

app.get('/login', (req, res) => res.render('login', { error: null }));
app.get('/dashboard', authenticateToken, async (req, res) => {
  const user = await User.findById(req.user.id);
  res.render('dashboard', { user });
});
app.get('/recipes', authenticateToken, async (req, res) => {
  const recipes = await Recipe.find();
  res.render('recipes', { recipes });
});

// Register User

app.post('/register', async (req, res) => {
  const { username, email, password, role } = req.body;

  // Basic validation
  if (!username || !email || !password || !role) {
    return res.render('register', { error: 'All fields are required.' });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.render('register', { error: 'Email already registered.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, email, password: hashedPassword, role });
    await user.save();

    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET);
    res.cookie('token', token).redirect('/login');
  } catch (err) {
    console.error(err);
    res.render('register', { error: 'Server Error. Please try again.' });
  }
});


// Login User
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.render('login', { error: 'All fields are required.' });
  }

  try {
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.render('login', { error: 'Invalid credentials.' });
    }

    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET);
    res.cookie('token', token).redirect('/dashboard');
  } catch (err) {
    console.error(err);
    res.render('login', { error: 'Server Error. Please try again.' });
  }
});

// Logout
app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/');
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
    const { name, ingredient, cuisine, mealType, difficulty, maxPrepTime } = req.query;
    const filter = {};

    if (name) {
      filter.name = { $regex: name, $options: 'i' };
    }

    if (ingredient) {
      filter['ingredients.name'] = { $regex: ingredient, $options: 'i' };
    }

    if (cuisine) {
      filter.cuisine = { $regex: cuisine, $options: 'i' };
    }

    if (mealType) {
      filter.mealType = { $regex: mealType, $options: 'i' };
    }

    if (difficulty) {
      filter.difficulty = difficulty;
    }

    if (maxPrepTime) {
      filter.prepTime = { $lte: parseInt(maxPrepTime) };
    }

    const recipes = await Recipe.find(filter);
    res.json(recipes);
  } catch (err) {
    console.error('Error fetching recipes:', err);
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

// Ingredient Routes
app.post('/api/ingredients', authenticateToken, async (req, res) => {
  try {
    const ingredient = new Ingredient(req.body);
    await ingredient.save();
    res.status(201).json(ingredient);
  } catch (err) {
    res.status(400).json({ message: 'Error creating ingredient' });
  }
});

app.get('/api/ingredients', async (req, res) => {
  try {
    const ingredients = await Ingredient.find();
    res.json(ingredients);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching ingredients' });
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

// Port
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

