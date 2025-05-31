const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const router = express.Router();

// Login endpoint
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Validate input
    if (!username || !password) {
      return res.status(400).json({
        message: 'Please provide both username and password'
      });
    }

    // Find user
    const user = await User.findOne({ username: username.toLowerCase().trim() });
    if (!user) {
      return res.status(401).json({
        message: 'Invalid username or password'
      });
    }

    // Check if user is active
    if (!user.isActive) {
      return res.status(401).json({
        message: 'Account is disabled'
      });
    }

    // Verify password
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      return res.status(401).json({
        message: 'Invalid username or password'
      });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Generate JWT token
    const token = jwt.sign(
      { 
        userId: user._id, 
        username: user.username,
        role: user.role 
      },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        role: user.role,
        lastLogin: user.lastLogin
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      message: 'Server error during login'
    });
  }
});

// Verify token endpoint
router.get('/verify', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    
    if (!user || !user.isActive) {
      return res.status(401).json({ message: 'Invalid token' });
    }

    res.json({
      message: 'Token is valid',
      user: {
        id: user._id,
        username: user.username,
        role: user.role
      }
    });

  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
});

// Create default admin user (for setup only)
router.post('/setup', async (req, res) => {
  try {
    // Check if any users exist
    const userCount = await User.countDocuments();
    if (userCount > 0) {
      return res.status(400).json({
        message: 'Setup already completed'
      });
    }

    // Create default admin user
    const adminUser = new User({
      username: 'admin',
      password: 'admin123' // Change this in production!
    });

    await adminUser.save();

    res.json({
      message: 'Default admin user created successfully',
      username: 'admin',
      defaultPassword: 'admin123'
    });

  } catch (error) {
    console.error('Setup error:', error);
    res.status(500).json({
      message: 'Error creating admin user'
    });
  }
});

module.exports = router;