const db = require('../config/database');

// ========================================
// GET ACTIVITIES
// ========================================

const getActivities = async (req, res) => {
  try {
    const {
      location = '',
      page = 1,
      limit = 6
    } = req.query;

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
      query += ' WHERE a.location LIKE ?';
      params.push(`%${location}%`);
    }

    query += ` LIMIT ${limitNum} OFFSET ${offset}`;

    const [rows] = await db.execute(query, params);

    res.json(rows);

  } catch (err) {
    console.error('❌ Fetch activities failed:', err);

    res.status(500).json({
      error: 'Server error'
    });
  }
};


// ========================================
// ADD ACTIVITY
// ========================================

const addActivity = async (req, res) => {
  const {
    title,
    description,
    location,
    price,
    date_available,
    category_id,
    image_url
  } = req.body;

  // Get admin ID from session
  const created_by = req.session && req.session.adminId;

  // Validate required fields
  if (
    !title ||
    !description ||
    !location ||
    !price ||
    !date_available ||
    !category_id ||
    !image_url ||
    !created_by
  ) {
    return res.status(400).json({
      success: false,
      message: 'All fields are required including admin session'
    });
  }

  try {
    const [result] = await db.execute(
      `
      INSERT INTO activities
      (
        title,
        description,
        location,
        price,
        date_available,
        category_id,
        image_url,
        created_by
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `,
      [
        title,
        description,
        location,
        price,
        date_available,
        category_id,
        image_url,
        created_by
      ]
    );

    res.status(201).json({
      success: true,
      message: 'Activity added successfully',
      id: result.insertId
    });

  } catch (err) {
    console.error('❌ Activity Insert Error:', err);

    res.status(500).json({
      success: false,
      message: 'Failed to add activity'
    });
  }
};

// ========================================
// GET SINGLE ACTIVITY BY ID
// ========================================

const getActivityById = async (req, res) => {
  const { id } = req.params;

  if (!id || isNaN(id)) {
    return res.status(400).json({
      success: false,
      message: 'Invalid activity ID'
    });
  }

  try {
    const [rows] = await db.execute(
      `
      SELECT 
        a.*,
        c.name AS category_name
      FROM activities a
      LEFT JOIN categories c ON a.category_id = c.id
      WHERE a.id = ?
      LIMIT 1
      `,
      [id]
    );

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        message: 'Activity not found'
      });
    }

    res.json(rows[0]);

  } catch (err) {
    console.error('❌ Fetch single activity failed:', err);

    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};


// ========================================
// EXPORT
// ========================================

module.exports = {
  getActivities,
  getActivityById,
  addActivity
};