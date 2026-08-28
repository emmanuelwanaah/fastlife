// server.js

require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const http = require('http');
const socketIO = require('socket.io');
const path = require('path');
const cors = require('cors');

// Routes
const authRoutes = require('./routes/authRoutes');
const adminRoutes = require('./routes/adminRoutes');
const exploreRoutes = require('./routes/exploreRoutes');
const activityRoutes = require('./routes/activityRoutes');
const categoryRoutes = require('./routes/categoryRoutes');
const wishlistRoutes = require('./routes/wishlistRoutes');
const bookingRoutes = require('./routes/bookingRoutes');

const app = express();
const server = http.createServer(app);
const io = socketIO(server);

// ========================================
// MIDDLEWARE
// ========================================

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  cors({
    origin: 'https://www.fastlifetraveltour.com',
    credentials: true
  })
);

// ========================================
// REDIRECT NON-WWW TO WWW
// ========================================

app.use((req, res, next) => {
  if (req.headers.host === 'fastlifetraveltour.com') {
    return res.redirect(
      301,
      'https://www.fastlifetraveltour.com' + req.originalUrl
    );
  }

  next();
});

// ========================================
// SESSION
// ========================================

const sessionStore = new MySQLStore({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

app.use(
  session({
    secret: process.env.SESSION_SECRET || 'default_secret',
    resave: false,
    saveUninitialized: false,
    store: sessionStore,

    cookie: {
      maxAge: 60 * 60 * 1000
    }
  })
);

// ========================================
// STATIC FILES
// ========================================

app.use(express.static(path.join(__dirname, 'views')));
app.use(express.static(path.join(__dirname, 'public')));

// ========================================
// HOME PAGE
// ========================================

app.get('/', (req, res) => {
  res.sendFile(
    path.join(__dirname, 'views', 'index.html')
  );
});

// ========================================
// ROUTES
// ========================================

app.use('/', authRoutes);
app.use('/', adminRoutes);
app.use('/', exploreRoutes);
app.use('/api/activities', activityRoutes);
app.use('/', categoryRoutes);
app.use('/', wishlistRoutes);
app.use('/', bookingRoutes);

// ========================================
// ROUTE PROTECTION
// ========================================

app.use((req, res, next) => {
  const publicPaths = [
    '/',
    '/login',
    '/register',
    '/login.html',
    '/adminlogin.html'
  ];

  // Allow public pages and API routes
  if (
    publicPaths.includes(req.path) ||
    req.path.startsWith('/api')
  ) {
    return next();
  }

  // Protect admin page
  if (
    req.path === '/admin.html' &&
    !req.session.adminId
  ) {
    return res.redirect('/adminlogin.html');
  }

  // Protect user pages
  if (!req.session.userId) {
    return res.redirect('/login.html');
  }

  next();
});

// ========================================
// 404 HANDLER
// ========================================

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found'
  });
});

// ========================================
// START SERVER
// ========================================

const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});