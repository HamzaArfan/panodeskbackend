require('dotenv').config();

// Configuration file - contains environment variables
// Note: In production, these should be actual environment variables

const config = {
  // Database
  DATABASE_URL: process.env.DATABASE_URL || "prisma+postgres://accelerate.prisma-data.net/?api_key=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhcGlfa2V5IjoiMDFKWDA4UkI5ODAzMVpDVkJOVlJHMUg0RkciLCJ0ZW5hbnRfaWQiOiI5ODMxNDVlYmExNWFkNzczNmYxMDk2MmM1YzhjN2ZlMjY2MGVlZTRkYTYzY2QyYzZmNjZiOTlhZWYzMDBiYzcwIiwiaW50ZXJuYWxfc2VjcmV0IjoiYjMwZTJkMTItOGQwZS00MThlLTk2M2MtNjk5NWJhZjM2YjM3In0.5UJ7EhbpWUdQVA5_I661s2EUJZ6SKlkEDuczU63Mdy8",

  // JWT
  JWT_SECRET: process.env.JWT_SECRET || "your-super-secret-jwt-key-here-make-this-very-long-and-random-for-security",
  JWT_REFRESH_SECRET: process.env.JWT_REFRESH_SECRET || "your-refresh-secret-here-also-very-long-and-random-for-security",

  // Email (Gmail configuration - update with your actual email settings)
  EMAIL_HOST: process.env.EMAIL_HOST || "smtp.gmail.com",
  EMAIL_PORT: parseInt(process.env.EMAIL_PORT) || 587,
  EMAIL_USER: process.env.EMAIL_USER || "your-email@gmail.com",
  EMAIL_PASS: process.env.EMAIL_PASS || "your-app-password", // Use App Password for Gmail
  EMAIL_FROM: process.env.EMAIL_FROM || "your-email@gmail.com",

  // App URLs
  APP_URL: process.env.APP_URL || "http://localhost:3000",
  API_URL: process.env.API_URL || "http://localhost:5001",
  NODE_ENV: process.env.NODE_ENV || "development",

  // Rate Limiting
  RATE_LIMIT_WINDOW_MS: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 900000, // 15 minutes
  RATE_LIMIT_MAX_REQUESTS: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100
};

// Set environment variables from config
Object.keys(config).forEach(key => {
  if (!process.env[key]) {
    process.env[key] = config[key];
  }
});

module.exports = config; 