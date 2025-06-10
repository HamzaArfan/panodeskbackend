# Panodesk Backend

Backend API server for the Panodesk application built with Express.js and Prisma.

## Features

- RESTful API with Express.js
- Database integration with Prisma ORM
- Authentication with JWT
- Email functionality with Nodemailer
- Rate limiting and security middleware
- CORS support

## Setup

1. Clone the repository
```bash
git clone https://github.com/HamzaArfan/panodeskbackend.git
cd panodeskbackend
```

2. Install dependencies
```bash
npm install
```

3. Set up environment variables
```bash
cp .env.example .env
```
Edit the `.env` file with your database URL and other configuration values.

4. Set up the database
```bash
npm run db:migrate
npm run db:seed
```

5. Start the development server
```bash
npm run dev
```

The server will start on http://localhost:5000

## Production Deployment

This backend is designed to be deployed on Railway. The `package.json` includes the necessary scripts and configuration for Railway deployment.

## Environment Variables

See `.env.example` for required environment variables.

## API Documentation

The API provides endpoints for:
- User authentication
- Data management
- File operations

## Tech Stack

- Node.js
- Express.js
- Prisma ORM
- PostgreSQL
- JWT Authentication 