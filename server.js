// Load configuration first
require('./config');

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
require('dotenv').config();

const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const organizationRoutes = require('./routes/organizations');
const projectRoutes = require('./routes/projects');
const tourRoutes = require('./routes/tours');
const commentRoutes = require('./routes/comments');
const invitationRoutes = require('./routes/invitations');

const { errorHandler } = require('./middleware/errorHandler');
const { authenticate } = require('./middleware/auth');

const app = express();
const PORT = process.env.PORT || 5001;

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});

// CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    // Define allowed origins
    const allowedOrigins = [
      'http://localhost:3000', // Development
      'http://localhost:3001', // Alternative development port
      process.env.APP_URL, // Production frontend URL from environment
    ].filter(Boolean); // Remove any undefined values
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
};

// Middleware
app.use(helmet());
app.use(limiter);
app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Public routes
app.use('/api/auth', authRoutes);

// Protected routes
app.use('/api/users', authenticate, userRoutes);
app.use('/api/organizations', authenticate, organizationRoutes);
app.use('/api/projects', authenticate, projectRoutes);
app.use('/api/tours', authenticate, tourRoutes);
app.use('/api/comments', authenticate, commentRoutes);
app.use('/api/invitations', authenticate, invitationRoutes);

// Error handling
app.use(errorHandler);

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found'
  });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV}`);
}); 