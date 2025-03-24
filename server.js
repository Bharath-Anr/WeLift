const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your_secret_key';

// ✅ MongoDB Connection
console.log("🚀 Starting WeLift server...");
mongoose.connect('mongodb://localhost:27017/welift')
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch(err => console.error("❌ MongoDB connection error:", err));

// ✅ Models
const User = mongoose.model('User', {
  name: String,
  username: { type: String, unique: true },
  password: String,
  email: String,
  createdAt: { type: Date, default: Date.now },
  lastLogin: Date
});

const Workout = mongoose.model('Workout', {
  userId: mongoose.Schema.Types.ObjectId,
  username: String,  // ✅ Store username for easy verification
  name: String,  // ✅ Store full name
  date: { type: Date, default: Date.now },
  totalCount: Number,
  correctCount: Number,
  incorrectCount: Number
});

// ✅ Middleware
app.use(express.json());
app.use(cors());

// ✅ Authentication Middleware
const authenticateUser = (req, res, next) => {
  const token = req.header('x-auth-token');
  if (!token) return res.status(401).json({ message: 'No token, authorization denied' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

// ✅ Register New User
app.post('/api/register', async (req, res) => {
  try {
    const { name, username, password, email } = req.body;
    const existingUser = await User.findOne({ username });
    if (existingUser) return res.status(400).json({ message: 'Username already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, username, password: hashedPassword, email });
    await user.save();

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1d' });
    res.status(201).json({ message: 'User registered successfully', token });
  } catch (error) {
    res.status(500).json({ message: 'Error registering user', error: error.message });
  }
});

// ✅ User Login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ message: 'Invalid username or password' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ message: 'Invalid username or password' });

    user.lastLogin = new Date();
    await user.save();

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1d' });
    res.status(200).json({ message: 'Login successful', token });
  } catch (error) {
    res.status(500).json({ message: 'Error logging in', error: error.message });
  }
});

// ✅ Get User Profile
app.get('/api/profile', authenticateUser, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    res.status(200).json({ user });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching profile', error: error.message });
  }
});

// ✅ Save a Workout (Each workout stored separately, includes username & name)
app.post('/api/workouts', authenticateUser, async (req, res) => {
  try {
    const { totalCount, correctCount, incorrectCount } = req.body;

    // ✅ Fetch user details to include username & name
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    const workout = new Workout({
      userId: req.user.userId,
      username: user.username,  // ✅ Store username
      name: user.name,  // ✅ Store full name
      date: new Date(),
      totalCount,
      correctCount,
      incorrectCount
    });

    await workout.save();
    res.status(201).json({ message: 'Workout saved successfully', workout });

  } catch (error) {
    res.status(500).json({ message: 'Error saving workout', error: error.message });
  }
});

// ✅ Get All Workouts (List Separately, Includes Username)
app.get('/api/workouts', authenticateUser, async (req, res) => {
  try {
    const workouts = await Workout.find({ userId: req.user.userId }).sort({ date: -1 });
    res.status(200).json(workouts);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching workouts', error: error.message });
  }
});

// ✅ Start Server
app.listen(port, () => {
  console.log(`✅ WeLift server is running on http://localhost:${port}`);
});
