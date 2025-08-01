// server.js
const express = require('express');
const mysql = require('mysql2/promise');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const http = require('http');
const socketIO = require('socket.io');
const stripe = require('stripe')(process.env.STRIPE_SECRET);
const path = require('path');
const cors = require('cors');

if (process.env.NODE_ENV !== 'production') require('dotenv').config();

const { validateAndHashPassword } = require('./utils/passwords');
const { sendVerificationCode } = require('./utils/emails');

const app = express();
const server = http.createServer(app);
const io = socketIO(server);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));


app.use(cors({
  origin: 'https://www.fastlifetraveltour.com', // your frontend domain
  credentials: true // allow cookies (like session ID) to be sent
}));




// // CORS for Railway (same-origin frontend + backend)
// app.use(cors({
//   origin: 'https://fastlife-production.up.railway.app',
//   credentials: true
// }));

// Redirect non-www to www
app.use((req, res, next) => {
  if (req.headers.host === 'fastlifetraveltour.com') {
    return res.redirect(301, 'https://www.fastlifetraveltour.com' + req.originalUrl);
  }
  next();
});



const MySQLStore = require('express-mysql-session')(session);

const sessionStore = new MySQLStore({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

app.use(session({
  secret: process.env.SESSION_SECRET || 'default_secret',
  resave: false,
  saveUninitialized: false,
  store: sessionStore,
  cookie: { maxAge: 60 * 60 * 1000 }
}));
 



// Serve static files in production too
app.use(express.static(path.join(__dirname, 'views')));
app.use(express.static(path.join(__dirname, 'public')));

// Optional: fallback to index.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'index.html'));
});


// DB Connection
// Connection Pool Setup
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: { rejectUnauthorized: false },
  waitForConnections: true,
  connectionLimit: 10, // You can adjust based on expected load
  queueLimit: 0
});

const db = pool;


db.getConnection()
  .then(() => console.log("✅ Connected to Railway DB via pool"))
  .catch(err => console.error("❌ Pool connection error:", err));


// ROUTES: Insert your existing routes here exactly as written (login, register, bookings, wishlist, etc.)
// Paste from your full server code
// Admin Login
app.post('/adminlogin', async (req, res) => {
    const { email, password } = req.body;
    try {
      const [rows] = await db.query('SELECT * FROM admins WHERE email = ?', [email]);
      if (!rows.length || rows[0].password !== password)
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
      req.session.adminId = rows[0].id;
      res.json({ success: true });
    } catch (err) {
      console.error('Admin login error:', err);
      res.status(500).json({ success: false, message: 'Server error' });
    }
  });
  
  // User Login
  app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
      const [rows] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
      if (!rows.length || !(await bcrypt.compare(password, rows[0].password)))
        return res.json({ success: false, message: 'Invalid email or password' });
  
      const user = rows[0];
      req.session.userId = user.id;
      req.session.firstName = user.first_name;
      req.session.lastName = user.last_name;
      req.session.email = user.email;
      req.session.userName = `${user.first_name} ${user.last_name}`;
      res.json({ success: true });
    } catch (err) {
      console.error('Login error:', err);
      res.json({ success: false, message: 'Server error' });
    }
  });
  
  // Registration
  app.post('/register', async (req, res) => {
    const { first_name, last_name, email, phone, password } = req.body;
    try {
      const [existing] = await db.execute('SELECT id FROM users WHERE email = ?', [email]);
      if (existing.length)
        return res.status(400).json({ success: false, message: 'Email already registered' });
  
      const result = await validateAndHashPassword(password);
      if (!result.success)
        return res.status(400).json({ success: false, message: result.message });
  
      const [insert] = await db.execute(`
        INSERT INTO users (first_name, last_name, email, phone, password, created_at)
        VALUES (?, ?, ?, ?, ?, NOW())`,
        [first_name, last_name, email, phone, result.hash]);
  
      req.session.userId = insert.insertId;
      req.session.userName = `${first_name} ${last_name}`;
      req.session.email = email;
      res.json({ success: true });
    } catch (err) {
      console.error('Registration error:', err);
      res.status(500).json({ success: false, message: 'Registration failed' });
    }
  });
  
  // Password Reset Flow
  app.post('/api/request-password-reset', async (req, res) => {
    const { email, newPassword } = req.body;
    if (!email || !newPassword)
      return res.status(400).json({ success: false, message: "Email and new password required." });
  
    const [rows] = await db.execute("SELECT password FROM users WHERE email = ?", [email]);
    if (!rows.length)
      return res.status(400).json({ success: false, message: "Email not found." });
  
    const result = await validateAndHashPassword(newPassword, rows[0].password);
    if (!result.success)
      return res.status(400).json({ success: false, message: result.message });
  
    const code = Math.floor(100000 + Math.random() * 900000);
    req.session.resetEmail = email;
    req.session.resetHash = result.hash;
    req.session.resetCode = code;
    req.session.resetExpires = Date.now() + 10 * 60 * 1000;
    await sendVerificationCode(email, code);
    res.json({ success: true, message: "Verification code sent." });
  });
  
  app.post('/api/verify-reset-code', async (req, res) => {
    const { code } = req.body;
    const session = req.session;
    if (!session.resetCode || !session.resetEmail || !session.resetHash || !session.resetExpires)
      return res.status(400).json({ success: false, message: "Invalid session." });
  
    if (Date.now() > session.resetExpires)
      return res.status(400).json({ success: false, message: "Code expired." });
  
    if (parseInt(code) !== parseInt(session.resetCode))
      return res.status(400).json({ success: false, message: "Incorrect code." });
  
    await db.execute("UPDATE users SET password = ? WHERE email = ?", [session.resetHash, session.resetEmail]);
  
    delete session.resetCode;
    delete session.resetEmail;
    delete session.resetHash;
    delete session.resetExpires;
  
    res.json({ success: true, message: "Password reset successful." });
  });
  
  // Session Info
  app.get('/session', (req, res) => {
    if (req.session.userId) {
      return res.json({
        loggedIn: true,
        userId: req.session.userId,
        firstName: req.session.firstName,
        lastName: req.session.lastName,
        email: req.session.email
      });
    }
    res.json({ loggedIn: false });
  });
  app.get('/admin/session', (req, res) => {
    if (req.session.adminId)
      return res.json({ loggedIn: true, adminId: req.session.adminId });
    res.json({ loggedIn: false });
  });
  
  // Logout
  app.post('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/login.html'));
  });
  
  // All APIs
  
      
  
  
  
  
      
  
      // Explore APIs
      app.get('/api/explore', async (req, res) => {
          try {
            const { search = '', page = 1, limit = 6, excludeId } = req.query;
            const pageNum = parseInt(page);
            const limitNum = parseInt(limit);
            const offset = (pageNum - 1) * limitNum;
    
            let query = 'SELECT * FROM explore';
            const params = [];
            let whereAdded = false;
    
            if (search.trim()) {
              query += ' WHERE title LIKE ? OR location LIKE ?';
              params.push(`%${search}%`, `%${search}%`);
              whereAdded = true;
            }
    
            if (excludeId) {
              query += whereAdded ? ' AND id != ?' : ' WHERE id != ?';
              params.push(excludeId);
            }
    
            query += ` LIMIT ${limitNum} OFFSET ${offset}`;
            const [rows] = await db.execute(query, params);
            res.json(rows);
          } catch (err) {
            console.error('❌ Fetch explore failed:', err);
            res.status(500).json({ error: 'Internal Server Error' });
          }
        });
    
        app.get('/api/explore/:id', async (req, res) => {
          try {
            const [rows] = await db.execute('SELECT * FROM explore WHERE id = ?', [req.params.id]);
            if (!rows.length) return res.status(404).json({ error: 'Not found' });
            res.json(rows[0]);
          } catch (err) {
            console.error('❌ Fetch explore item failed:', err);
            res.status(500).json({ error: 'Server error' });
          }
        });
    
        // Activities
        app.get('/api/activities', async (req, res) => {
          try {
            const { location = '', page = 1, limit = 6 } = req.query;
            const pageNum = parseInt(page);
            const limitNum = parseInt(limit);
            const offset = (pageNum - 1) * limitNum;
    
            let query = `
              SELECT a.*, c.name AS category_name
              FROM activities a
              LEFT JOIN categories c ON a.category_id = c.id
            `;
            const params = [];
    
            if (location.trim()) {
              query += ' WHERE a.location LIKE ?';
              params.push(`%${location}%`);
            }
    
            query += ` LIMIT ${limitNum} OFFSET ${offset}`;
            const [rows] = await db.execute(query, params);
            res.json(rows);
          } catch (err) {
            console.error('❌ Fetch activities failed:', err);
            res.status(500).json({ error: 'Server error' });
          }
        });
    
        // Categories
        app.get('/api/categories', async (req, res) => {
          try {
            const [rows] = await db.execute('SELECT * FROM categories');
            res.json(rows);
          } catch (err) {
            console.error('❌ Fetch categories failed:', err);
            res.status(500).json({ error: 'Server error' });
          }
        });
    
        // Wishlist
        app.post('/api/wishlist', async (req, res) => {
          const userId = req.session.userId;
          const { activity_id } = req.body;
        
          if (!userId) return res.status(401).json({ error: 'Unauthorized' });
        
          try {
            // Check if already exists
            const [exists] = await db.execute(
              'SELECT 1 FROM wishlist WHERE user_id = ? AND activity_id = ?', [userId, activity_id]
            );
            if (exists.length) return res.status(409).json({ error: 'Already in wishlist' });
        
            // Get full activity details
            const [activityRows] = await db.execute(
              'SELECT title, image_url, location, price FROM activities WHERE id = ?', [activity_id]
            );
        
            if (!activityRows.length) return res.status(404).json({ error: 'Activity not found' });
        
            const { title, image_url, location, price } = activityRows[0];
        
            // Insert into wishlist with full info
            await db.execute(`
              INSERT INTO wishlist (user_id, activity_id, title, image_url, location, price)
              VALUES (?, ?, ?, ?, ?, ?)`,
              [userId, activity_id, title, image_url, location, price]
            );
        
            res.status(201).json({ success: true });
          } catch (err) {
            console.error('❌ Add wishlist failed:', err);
            res.status(500).json({ error: 'Server error' });
          }
        });
        
    
        app.delete('/api/wishlist', async (req, res) => {
          const userId = req.session.userId;
          const { activity_id } = req.body;
          if (!userId) return res.status(401).json({ error: 'Unauthorized' });
    
          try {
            const [result] = await db.execute(
              'DELETE FROM wishlist WHERE user_id = ? AND activity_id = ?', [userId, activity_id]
            );
            if (result.affectedRows === 0) return res.status(404).json({ error: 'Not found' });
            res.json({ success: true });
          } catch (err) {
            console.error('❌ Delete wishlist failed:', err);
            res.status(500).json({ error: 'Server error' });
          }
        });
    
        app.get('/api/wishlist', async (req, res) => {
          const userId = req.session.userId;
          if (!userId) return res.status(401).json({ error: 'Unauthorized' });
    
          try {
            const [rows] = await db.execute(`
              SELECT a.*, c.name AS category_name
              FROM wishlist w
              JOIN activities a ON w.activity_id = a.id
              LEFT JOIN categories c ON a.category_id = c.id
              WHERE w.user_id = ?
              ORDER BY w.created_at DESC
            `, [userId]);
            res.json(rows);
          } catch (err) {
            console.error('❌ Get wishlist failed:', err);
            res.status(500).json({ error: 'Server error' });
          }
        });
    
        app.delete('/api/wishlist/all', async (req, res) => {
          const userId = req.session.userId;
          if (!userId) return res.status(401).json({ error: 'Unauthorized' });
    
          try {
            await db.execute('DELETE FROM wishlist WHERE user_id = ?', [userId]);
            res.json({ success: true });
          } catch (err) {
            console.error('❌ Clear wishlist failed:', err);
            res.status(500).json({ error: 'Server error' });
          }
        });
      
        
        
        // Booking
        const generateBookingRef = () => 'REF' + Math.floor(100000000 + Math.random() * 900000000);
    
          
  // Add at the top:
  app.post('/api/create-checkout-session', async (req, res) => {
    try {
      const userId = req.session.userId;
      if (!userId) return res.status(401).json({ error: 'Unauthorized' });
  
      const { activities, total, dateRange, nights } = req.body;
  
      if (!Array.isArray(activities) || activities.length === 0 || !total || !dateRange) {
        return res.status(400).json({ error: 'Invalid booking data' });
      }
  
      const lineItems = activities.map(act => ({
        price_data: {
          currency: 'eur',
          product_data: {
            name: act.title,
            images: [act.image],
            description: `${act.location} | ${dateRange} (${nights})`
          },
          unit_amount: Math.round(Number(act.price) * 100)
        },
        quantity: 1
      }));
  
      const session = await stripe.checkout.sessions.create({
        payment_method_types: ['card'],
        mode: 'payment',
        line_items: lineItems,
        success_url: 'https://www.fastlifetraveltour.com/completedbookings.html',
        cancel_url: 'https://www.fastlifetraveltour.com/bookings.html',
        metadata: {
          userId: userId.toString(),
          dateRange,
          nights,
          total: total.toString()
          // ⚠️ You can also serialize activity IDs here for saving later if needed
        }
      });
  
      res.json({ id: session.id });
  
    } catch (error) {
      console.error('❌ Error creating Stripe session:', error);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  });
  
  
  

  app.post('/api/confirm-booking', async (req, res) => {
    const userId = req.session.userId;
    const { reference, dateRange, nights, total, activities } = req.body;
  
    if (!userId || !reference || !activities || !Array.isArray(activities)) {
      return res.status(400).json({ success: false, message: 'Invalid booking data.' });
    }
  
    try {
      const now = new Date();
  
      for (const activity of activities) {
        if (!activity?.id || isNaN(activity.price)) {
          console.warn('⚠️ Skipping invalid activity:', activity);
          continue;
        }
  
        // ✅ Insert booking
        await db.execute(
          `INSERT INTO bookings (
            user_id,
            activity_id,
            booking_reference,
            total_price,
            date_range,
            created_at,
            payment_status,
            status
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            userId,
            activity.id,
            reference,
            parseFloat(activity.price),
            dateRange,
            now,
            'paid',
            'confirmed'
          ]
        );
  
        // ✅ Remove from wishlist (if exists)
        await db.execute(
          `DELETE FROM wishlist WHERE user_id = ? AND activity_id = ?`,
          [userId, activity.id]
        );
      }
  
      res.json({ success: true });
    } catch (err) {
      console.error('❌ Failed to insert booking:', err.message);
      res.status(500).json({ success: false, message: 'Database error' });
    }
  });
  
  

  // FETCH COMPLETED BOOKINGS
  // FETCH COMPLETED BOOKINGS
  app.get('/api/completed-bookings', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });
  
    try {
      const [bookings] = await db.query(
        `SELECT 
           b.booking_reference AS reference,
           a.title,
           a.image_url AS image, -- ✅ pull from activities
           a.location,
           b.date_range,
           b.total_price AS price
         FROM bookings b
         JOIN activities a ON b.activity_id = a.id
         WHERE b.user_id = ?
         ORDER BY b.created_at DESC`,
        [userId]
      );
      
      res.json({ bookings });
    } catch (err) {
      console.error('Error fetching completed bookings:', err);
      res.status(500).json({ error: 'Failed to load bookings' });
    }
  });
  
  
    
    
    
    
    
    
    app.post('/logout', (req, res) => {
      req.session.destroy(err => {
        if (err) {
          console.error('❌ Session destruction error:', err);
          return res.status(500).json({ success: false, message: 'Logout failed' });
        }
    
        res.clearCookie('connect.sid');
        res.json({ success: true });
      });
    });
    
    
    
    
    
    
    
    
    // Add Category
    app.post('/api/categories', (req, res) => {
      const { name, description, image_url } = req.body;
    
      if (!name || !description || !image_url) {
        return res.status(400).json({ message: 'All fields are required' });
      }
    
      const sql = 'INSERT INTO categories (name, description, image_url) VALUES (?, ?, ?)';
      db.query(sql, [name, description, image_url], (err, result) => {
        if (err) {
          console.error('Category Insert Error:', err);
          return res.status(500).json({ message: 'Failed to add category' });
        }
        res.status(200).json({ message: 'Category added successfully', id: result.insertId });
      });
    });
    app.post('/api/experiences', (req, res) => {
      const { title, location, category, rating, duration_minutes, price, image_url, description } = req.body;
    
      // Validate required fields
      if (!title || !location || !category || !rating || !duration_minutes || !price || !image_url || !description) {
        return res.status(400).json({ message: 'All fields are required' });
      }
    
      const sql = `
        INSERT INTO explore 
          (title, location, category, rating, duration_minutes, price, image_url, description)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `;
    
      db.query(sql, [title, location, category, rating, duration_minutes, price, image_url, description], (err, result) => {
        if (err) {
          console.error('Experience Insert Error:', err);
          return res.status(500).json({ message: 'Failed to add experience' });
        }
        res.status(200).json({ message: 'Experience added successfully', id: result.insertId });
      });
    });
    
    
    
    // Add Activity
    app.post('/api/activities', (req, res) => {
      const { title, description, location, price, date_available, category_id, image_url } = req.body;
      const created_by = req.session && req.session.adminId; // assumes session holds adminId
    
      // Validate required fields
      if (!title || !description || !location || !price || !date_available || !category_id || !image_url || !created_by) {
        return res.status(400).json({ message: 'All fields are required including admin session' });
      }
    
      const sql = `
        INSERT INTO activities 
        (title, description, location, price, date_available, category_id, image_url, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `;
    
      const values = [title, description, location, price, date_available, category_id, image_url, created_by];
    
      db.query(sql, values, (err, result) => {
        if (err) {
          console.error('Activity Insert Error:', err);
          return res.status(500).json({ message: 'Failed to add activity' });
        }
    
        res.status(200).json({ message: 'Activity added successfully', id: result.insertId });
      });
    });
    // Get all categories
    app.get('/api/categories', (req, res) => {
      db.query('SELECT id, name FROM categories', (err, results) => {
        if (err) {
          console.error('Category Fetch Error:', err);
          return res.status(500).json({ message: 'Failed to load categories' });
        }
        res.json(results);
      });
    });
    // DELETE /api/categories/:id
    
    // DELETE /api/experiences/:id
    
      // Get Activities (filtered by location)
    app.get('/api/activities', async (req, res) => {
      try {
        const { location = '', page = 1, limit = 6 } = req.query;
        const pageNum = parseInt(page, 10);
        const limitNum = parseInt(limit, 10);
        const offset = (pageNum - 1) * limitNum;
    
        let query = `
          SELECT a.*, c.name AS category_name
          FROM activities a
          LEFT JOIN categories c ON a.category_id = c.id
        `;
        const params = [];
    
        if (location.trim()) {
          query += ` WHERE a.location LIKE ?`;
          params.push(`%${location}%`);
        }
    
        query += ` ORDER BY a.date_available ASC LIMIT ? OFFSET ?`;
        params.push(limitNum, offset);
    
        const [rows] = await db.execute(query, params);
        res.json(rows);
      } catch (err) {
        console.error('❌ Fetch activities failed:', err);
        res.status(500).json({ error: 'Server error' });
      }
    });
    

// Middleware: Route Protection
app.use((req, res, next) => {
  const publicPaths = ['/', '/login', '/register', '/login.html', '/adminlogin.html'];
  if (publicPaths.includes(req.path) || req.path.startsWith('/api')) return next();

  if (req.path === '/admin.html' && !req.session.adminId)
    return res.redirect('/adminlogin.html');

  if (!req.session.userId)
    return res.redirect('/login.html');

  next();
});

// 404 Handler
app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Route not found' });
});

// Start Server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
