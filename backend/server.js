const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.NODE_ENV === 'production' ? ['https://your-app.vercel.app'] : ['http://localhost:3000'],
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Body parser middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => {
  console.log('✅ Connected to MongoDB Atlas successfully!');
})
.catch((error) => {
  console.error('❌ MongoDB connection error:', error);
  process.exit(1);
});

// Import routes
const authRoutes = require('./routes/auth');

// Use routes
app.use('/api/auth', authRoutes);

// Test route
app.get('/', (req, res) => {
  res.json({ 
    message: 'Jewellery Stock Management API is running!',
    status: 'success',
    timestamp: new Date().toISOString()
  });
});

// Health check route
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy',
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    timestamp: new Date().toISOString()
  });
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Server Error:', error);
  res.status(500).json({
    message: 'Something went wrong!',
    error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
  });
});

// Handle 404 routes
app.use('*', (req, res) => {
  res.status(404).json({
    message: 'Route not found',
    path: req.originalUrl
  });
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`🚀 Server is running on port ${PORT}`);
  console.log(`📱 API URL: http://localhost:${PORT}`);
  console.log(`🔗 Test URL: http://localhost:${PORT}/health`);
});