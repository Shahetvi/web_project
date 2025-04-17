// server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const connectDB = require('./database/connect');
const path = require('path');
const cookieParser = require('cookie-parser');
const session = require('express-session');

// Models
const User = require('./database/models/User');
const Recipe = require('./database/models/Recipe');
const Ingredient = require('./database/models/Ingredient');
const Review = require('./database/models/Review');
const MealPlan = require('./database/models/MealPlan');

const app = express();
connectDB();

// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(session({
  secret: process.env.SESSION_SECRET || 'keyboard cat',
  resave: false,
  saveUninitialized: true
}));

// Flash helper
app.use((req, res, next) => {
  res.locals.success = req.session.success;
  res.locals.error = req.session.error;
  delete req.session.success;
  delete req.session.error;
  next();
});

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

// Routes
app.get('/', (req, res) => res.render('login', { error: null }));
app.get('/register', (req, res) => res.render('register', { error: null }));
app.get('/login', (req, res) => res.render('login', { error: null }));

app.get('/dashboard', authenticateToken, async (req, res) => {
  const user = await User.findById(req.user.id);
  res.render('dashboard', { user });
});

app.get('/recipes', authenticateToken, async (req, res) => {
  const searchQuery = req.query.search?.trim().toLowerCase() || '';
  const message = req.query.message || null;
  const isAdmin = req.user && req.user.role === 'admin';

  let recipes = await Recipe.find().lean(); 

  if (searchQuery) {
    recipes = recipes.filter(recipe => {
      return (
        recipe.name.toLowerCase().includes(searchQuery) ||
        recipe.cuisine.toLowerCase().includes(searchQuery) ||
        recipe.mealType.toLowerCase().includes(searchQuery)
      );
    });
  }

  res.render('recipes', { recipes, message, isAdmin, searchQuery });
});

// View recipe (read-only)
app.get('/recipes/view/:id', authenticateToken, async (req, res) => {
  try {
    const recipe = await Recipe.findById(req.params.id);
    const ingredients = await Ingredient.find();
    const message = req.query.message || null;
    res.render('recipe-view', { recipe, ingredients, message  });
  } catch (err) {
    req.session.error = 'Failed to load recipe';
    res.redirect('/recipes');
  }
});


// Add new recipe
app.get('/recipes/new', authenticateToken, async (req, res) => {
  const ingredients = await Ingredient.find();
  const message = req.query.message || null;
  res.render('recipe-form', { recipe: null, ingredients, message });
});

// Edit existing recipe
app.get('/recipes/edit/:id', authenticateToken, async (req, res) => {
  const recipe = await Recipe.findById(req.params.id);
  const ingredients = await Ingredient.find();
  const message = req.query.message || null;
  res.render('recipe-form', { recipe, ingredients, message  });
});

// Add recipe (POST)
app.post('/recipes/new', authenticateToken, async (req, res) => {
  try {
    const ingredientInputs = req.body.ingredients || [];
    const fullIngredients = [];

    for (const item of ingredientInputs) {
      const ingredient = await Ingredient.findById(item.id);
      if (ingredient) {
        fullIngredients.push({
          name: ingredient.name,
          quantity: item.quantity,
          unit: item.unit
        });
      }
    }

    const recipe = new Recipe({
      name: req.body.name,
      cuisine: req.body.cuisine,
      mealType: req.body.mealType,
      ingredients: fullIngredients,
      instructions: req.body.instructions,
      difficulty: req.body.difficulty,
      nutrition: req.body.nutrition,
      prepTime: req.body.prepTime,
      author: req.user.id
    });

    await recipe.save();
    req.session.success = 'Recipe added successfully';
    res.redirect('/recipes');
  } catch (err) {
    console.error(err);
    req.session.error = 'Failed to add recipe';
    res.redirect('/recipes');
  }
});


// Update recipe
app.post('/recipes/update/:id', authenticateToken, async (req, res) => {
  try {
    const ingredientInputs = req.body.ingredients || [];
    const fullIngredients = [];

    for (const item of ingredientInputs) {
      const ingredient = await Ingredient.findById(item.id);
      if (ingredient) {
        fullIngredients.push({
          name: ingredient.name,
          quantity: item.quantity,
          unit: item.unit
        });
      }
    }

    const updatedRecipe = {
      name: req.body.name,
      cuisine: req.body.cuisine,
      mealType: req.body.mealType,
      ingredients: fullIngredients,
      instructions: req.body.instructions,
      difficulty: req.body.difficulty,
      nutrition: req.body.nutrition,
      prepTime: req.body.prepTime
    };

    await Recipe.findByIdAndUpdate(req.params.id, updatedRecipe);
    req.session.success = 'Recipe updated successfully';
    res.redirect('/recipes');
  } catch (err) {
    console.error(err);
    req.session.error = 'Failed to update recipe';
    res.redirect('/recipes');
  }
});



// Delete recipe
app.post('/recipes/:id/delete', authenticateToken, async (req, res) => {
  try {
    await Recipe.findByIdAndDelete(req.params.id);
    req.session.success = 'Recipe deleted successfully';
    res.redirect('/recipes');
  } catch (err) {
    req.session.error = 'Failed to delete recipe';
    res.redirect('/recipes');
  }
});

//View Recipe
app.get('/recipes/view/:id', authenticateToken, async (req, res) => {
  try {
    const recipe = await Recipe.findById(req.params.id);
    const ingredients = await Ingredient.find();
    const reviews = await Review.find({ recipe: req.params.id }).populate('user');
    const message = req.query.message || null;
    res.render('recipe-view', { recipe, ingredients, message, reviews });
  } catch (err) {
    req.session.error = 'Failed to load recipe';
    res.redirect('/recipes');
  }
});


// Add a new review
app.post('/recipes/:id/reviews/add', authenticateToken, async (req, res) => {
  const { rating, comment } = req.body;
  const recipeId = req.params.id;

  try {
    await Review.create({
      recipe: recipeId,
      user: req.user.id,
      rating,
      comment
    });
    res.redirect(`/recipes/${recipeId}/reviews`);
  } catch (err) {
    req.session.error = 'Failed to add review.';
    res.redirect(`/recipes/${recipeId}/reviews`);
  }
});

// Update an existing review
app.post('/recipes/:id/reviews/update', authenticateToken, async (req, res) => {
  const { rating, comment } = req.body;
  const recipeId = req.params.id;

  try {
    await Review.findOneAndUpdate(
      { recipe: recipeId, user: req.user.id },
      { rating, comment }
    );
    res.redirect(`/recipes/${recipeId}/reviews`);
  } catch (err) {
    req.session.error = 'Failed to update review.';
    res.redirect(`/recipes/${recipeId}/reviews`);
  }
});


// Get all reviews
app.get('/recipes/:id/reviews', authenticateToken, async (req, res) => {
  const recipeId = req.params.id;

  const recipe = await Recipe.findById(recipeId);
  const allReviews = await Review.find({ recipe: recipeId }).populate('user');

  const existingReview = await Review.findOne({ recipe: recipeId, user: req.user.id });

  res.render('reviews', {
    recipe,
    reviews: allReviews,
    userReview: existingReview,
    userId: req.user.id
  });
});

//Mealplan
app.get('/mealplan', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const week = getCurrentWeekString();

  const mealPlan = await MealPlan.findOne({ user: userId, week }).populate('days.recipes');

  res.render('mealplan', {
    user: req.user,
    week,
    mealPlan
  });
});

app.post('/mealplan-form', authenticateToken, async (req, res) => {
  const week = getCurrentWeekString();
  const existing = await MealPlan.findOne({ user: req.user.id, week });

  if (existing) {
    req.session.error = 'Meal plan already exists for this week.';
    return res.redirect('/mealplan');
  }

  const recipes = await Recipe.find();
  res.render('mealplan-form', { week, recipes });
});


app.post('/mealplan/save', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const week = getCurrentWeekString();
  const mealPlanData = req.body.mealPlan || {};

  const allDays = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];

  const days = allDays.map(day => {
    const recipes = mealPlanData[day];
    return {
      day,
      recipes: Array.isArray(recipes) ? recipes : (recipes ? [recipes] : [])
    };
  });

  let mealPlan = await MealPlan.findOne({ user: userId, week });
  if (mealPlan) {
    mealPlan.days = days;
    await mealPlan.save();
    req.session.success = 'Meal plan updated!';
  } else {
    mealPlan = new MealPlan({ user: userId, week, days });
    await mealPlan.save();
    req.session.success = 'Meal plan created!';
  }

  res.redirect('/mealplan');
});



function getCurrentWeekString() {
  const now = new Date();
  const oneJan = new Date(now.getFullYear(), 0, 1);
  const week = Math.ceil((((now - oneJan) / 86400000) + oneJan.getDay() + 1) / 7);
  return `${now.getFullYear()}-W${week.toString().padStart(2, '0')}`;
}


app.get('/mealplan-form', authenticateToken, async (req, res) => {
  const recipes = await Recipe.find(); 
  const week = getCurrentWeekString();
  const mealPlan = await MealPlan.findOne({ user: req.user.id, week }).populate('days.recipes');
  res.render('mealplan-form', { recipes, mealPlan, week });
});

app.post('/ingredients/new', authenticateToken, async (req, res) => {
  const { name, unit, description } = req.body;

  if (!name) {
    return res.status(400).json({ success: false, message: 'Name is required' });
  }

  try {
    const existing = await Ingredient.findOne({ name: name.trim() });
    if (existing) {
      return res.status(409).json({ success: false, message: 'Ingredient already exists' });
    }

    const ingredient = new Ingredient({ name: name.trim(), unit, description });
    await ingredient.save();

    res.json({ success: true, ingredient });
  } catch (err) {
    console.error('Error saving ingredient:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// User registration route
app.post('/register', async (req, res) => {
  const { username, email, password, role } = req.body;
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
    res.render('register', { error: 'Server Error. Please try again.' });
  }
});

// User login route
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
    res.render('login', { error: 'Server Error. Please try again.' });
  }
});

// User logout route
app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/');
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
