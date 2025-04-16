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

// Port
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
