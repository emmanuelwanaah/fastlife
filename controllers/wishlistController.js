const db = require('../config/database');

// ========================================
// ADD TO WISHLIST
// ========================================

const addToWishlist = async (req, res) => {
  const userId = req.session.userId;
  const { activity_id } = req.body;

  if (!userId) {
    return res.status(401).json({
      error: 'Unauthorized'
    });
  }

  try {
    // Check if already exists
    const [exists] = await db.execute(
      'SELECT 1 FROM wishlist WHERE user_id = ? AND activity_id = ?',
      [userId, activity_id]
    );

    if (exists.length) {
      return res.status(409).json({
        error: 'Already in wishlist'
      });
    }

    // Get full activity details
    const [activityRows] = await db.execute(
      'SELECT title, image_url, location, price FROM activities WHERE id = ?',
      [activity_id]
    );

    if (!activityRows.length) {
      return res.status(404).json({
        error: 'Activity not found'
      });
    }

    const {
      title,
      image_url,
      location,
      price
    } = activityRows[0];

    // Insert into wishlist
    await db.execute(
      `
        INSERT INTO wishlist
        (user_id, activity_id, title, image_url, location, price)
        VALUES (?, ?, ?, ?, ?, ?)
      `,
      [
        userId,
        activity_id,
        title,
        image_url,
        location,
        price
      ]
    );

    res.status(201).json({
      success: true
    });

  } catch (err) {
    console.error(
      '❌ Add wishlist failed:',
      err
    );

    res.status(500).json({
      error: 'Server error'
    });
  }
};


// ========================================
// REMOVE FROM WISHLIST
// ========================================

const removeFromWishlist = async (req, res) => {
  const userId = req.session.userId;
  const { activity_id } = req.body;

  if (!userId) {
    return res.status(401).json({
      error: 'Unauthorized'
    });
  }

  try {
    const [result] = await db.execute(
      'DELETE FROM wishlist WHERE user_id = ? AND activity_id = ?',
      [userId, activity_id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({
        error: 'Not found'
      });
    }

    res.json({
      success: true
    });

  } catch (err) {
    console.error(
      '❌ Delete wishlist failed:',
      err
    );

    res.status(500).json({
      error: 'Server error'
    });
  }
};


// ========================================
// GET USER WISHLIST
// ========================================

const getWishlist = async (req, res) => {
  const userId = req.session.userId;

  if (!userId) {
    return res.status(401).json({
      error: 'Unauthorized'
    });
  }

  try {
    const [rows] = await db.execute(
      `
        SELECT
          a.*,
          c.name AS category_name
        FROM wishlist w
        JOIN activities a
          ON w.activity_id = a.id
        LEFT JOIN categories c
          ON a.category_id = c.id
        WHERE w.user_id = ?
        ORDER BY w.created_at DESC
      `,
      [userId]
    );

    res.json(rows);

  } catch (err) {
    console.error(
      '❌ Get wishlist failed:',
      err
    );

    res.status(500).json({
      error: 'Server error'
    });
  }
};


// ========================================
// CLEAR ENTIRE WISHLIST
// ========================================

const clearWishlist = async (req, res) => {
  const userId = req.session.userId;

  if (!userId) {
    return res.status(401).json({
      error: 'Unauthorized'
    });
  }

  try {
    await db.execute(
      'DELETE FROM wishlist WHERE user_id = ?',
      [userId]
    );

    res.json({
      success: true
    });

  } catch (err) {
    console.error(
      '❌ Clear wishlist failed:',
      err
    );

    res.status(500).json({
      error: 'Server error'
    });
  }
};


module.exports = {
  addToWishlist,
  removeFromWishlist,
  getWishlist,
  clearWishlist
};