const db = require('../config/database');

// ========================================
// GET ALL EXPLORE ITEMS
// ========================================

const getExplore = async (req, res) => {
  try {
    const {
      search = '',
      page = 1,
      limit = 6,
      excludeId
    } = req.query;

    const pageNum = parseInt(page, 10);
    const limitNum = parseInt(limit, 10);
    const offset = (pageNum - 1) * limitNum;

    let query = 'SELECT * FROM explore';
    const params = [];
    let whereAdded = false;

    // Search
    if (search.trim()) {
      query += ' WHERE title LIKE ? OR location LIKE ?';
      params.push(`%${search}%`, `%${search}%`);
      whereAdded = true;
    }

    // Exclude ID
    if (excludeId) {
      query += whereAdded
        ? ' AND id != ?'
        : ' WHERE id != ?';

      params.push(excludeId);
    }

    // Pagination
    query += ` LIMIT ${limitNum} OFFSET ${offset}`;

    const [rows] = await db.execute(query, params);

    res.json(rows);

  } catch (err) {
    console.error('❌ Fetch explore failed:', err);

    res.status(500).json({
      error: 'Internal Server Error'
    });
  }
};


// ========================================
// GET SINGLE EXPLORE ITEM
// ========================================

const getExploreById = async (req, res) => {
  try {
    const [rows] = await db.execute(
      'SELECT * FROM explore WHERE id = ?',
      [req.params.id]
    );

    if (!rows.length) {
      return res.status(404).json({
        error: 'Not found'
      });
    }

    res.json(rows[0]);

  } catch (err) {
    console.error(
      '❌ Fetch explore item failed:',
      err
    );

    res.status(500).json({
      error: 'Server error'
    });
  }
};


// ========================================
// ADD EXPERIENCE
// ========================================

const addExperience = async (req, res) => {
  const {
    title,
    location,
    category,
    rating,
    duration_minutes,
    price,
    image_url,
    description
  } = req.body;

  // Validate required fields
  if (
    !title ||
    !location ||
    !category ||
    !rating ||
    !duration_minutes ||
    !price ||
    !image_url ||
    !description
  ) {
    return res.status(400).json({
      success: false,
      message: 'All fields are required'
    });
  }

  try {
    const [result] = await db.execute(
      `
      INSERT INTO explore
      (
        title,
        location,
        category,
        rating,
        duration_minutes,
        price,
        image_url,
        description
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `,
      [
        title,
        location,
        category,
        rating,
        duration_minutes,
        price,
        image_url,
        description
      ]
    );

    res.status(201).json({
      success: true,
      message: 'Experience added successfully',
      id: result.insertId
    });

  } catch (err) {
    console.error(
      '❌ Experience Insert Error:',
      err
    );

    res.status(500).json({
      success: false,
      message: 'Failed to add experience'
    });
  }
};


// ========================================
// EXPORT CONTROLLERS
// ========================================

module.exports = {
  getExplore,
  getExploreById,
  addExperience
};