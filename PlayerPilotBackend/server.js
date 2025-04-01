require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, { 
  useNewUrlParser: true, 
  useUnifiedTopology: true 
});

// User Schema
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, unique: true, sparse: true },
  password: { type: String, required: true },
  highScores: { type: Map, of: Number, default: {} },
  loginStreak: { type: Number, default: 0 },
  lastLogin: { type: Date }
});

const User = mongoose.model('User', UserSchema);

// Routes would go here...

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

// Register
app.post('/api/register', async (req, res) => {
    try {
      const { username, email, password } = req.body;
      
      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);
      
      const user = new User({
        username,
        email,
        password: hashedPassword
      });
      
      await user.save();
      
      // Create token
      const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
        expiresIn: '30d'
      });
      
      res.status(201).json({ token, user: { id: user._id, username } });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });
  
  // Login
  app.post('/api/login', async (req, res) => {
    try {
      const { username, password } = req.body;
      const user = await User.findOne({ username });
      
      if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      
      // Update login streak
      const now = new Date();
      const lastLogin = user.lastLogin || new Date(0);
      const daysSinceLastLogin = Math.floor((now - lastLogin) / (1000 * 60 * 60 * 24));
      
      let newStreak = user.loginStreak;
      if (daysSinceLastLogin === 1) {
        newStreak += 1;
      } else if (daysSinceLastLogin > 1) {
        newStreak = 1;
      }
      
      user.loginStreak = newStreak;
      user.lastLogin = now;
      await user.save();
      
      // Create token
      const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
        expiresIn: '30d'
      });
      
      res.json({ 
        token, 
        user: { 
          id: user._id, 
          username: user.username,
          loginStreak: user.loginStreak,
          highScores: user.highScores 
        }
      });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });
  
  // Middleware to protect routes
  const authMiddleware = async (req, res, next) => {
    const token = req.header('x-auth-token');
    if (!token) return res.status(401).json({ error: 'No token, authorization denied' });
    
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = await User.findById(decoded.id).select('-password');
      next();
    } catch (err) {
      res.status(401).json({ error: 'Token is not valid' });
    }
  };
  
  // Update high score
  app.post('/api/highscore', authMiddleware, async (req, res) => {
    try {
      const { game, score } = req.body;
      const user = req.user;
      
      if (!user.highScores.get(game) || score > user.highScores.get(game)) {
        user.highScores.set(game, score);
        await user.save();
      }
      
      res.json({ highScores: user.highScores });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });
  
  // Get user data
  app.get('/api/user', authMiddleware, async (req, res) => {
    res.json({
      user: {
        id: req.user._id,
        username: req.user.username,
        loginStreak: req.user.loginStreak,
        highScores: req.user.highScores
      }
    });
  });
