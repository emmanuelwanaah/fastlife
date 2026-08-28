const db = require('../config/database');

// ========================================
// GET CATEGORIES
// ========================================

const getCategories = async (req, res) => {
  try {
    const [rows] = await db.execute(
      'SELECT * FROM categories'
    );

    res.json(rows);

  } catch (err) {
    console.error('❌ Fetch categories failed:', err);

    res.status(500).json({
      error: 'Server error'
    });
  }
};

// ========================================
// ADD CATEGORY
// ========================================

const addCategory = async (req, res) => {
  const { name, description, image_url } = req.body;

  // Validate required fields
  if (!name || !description || !image_url) {
    return res.status(400).json({
      success: false,
      message: 'All fields are required'
    });
  }

  try {
    const [result] = await db.execute(
      `
      INSERT INTO categories
      (name, description, image_url)
      VALUES (?, ?, ?)
      `,
      [name, description, image_url]
    );

    res.status(201).json({
      success: true,
      message: 'Category added successfully',
      id: result.insertId
    });

  } catch (err) {
    console.error('❌ Category Insert Error:', err);

    res.status(500).json({
      success: false,
      message: 'Failed to add category'
    });
  }
};

module.exports = {
  getCategories,
  addCategory
};