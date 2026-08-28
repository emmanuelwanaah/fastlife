const express = require('express');

const {
  getCategories,
  addCategory
} = require('../controllers/categoryController');

const router = express.Router();

// Get all categories
router.get('/api/categories', getCategories);

// Add category
router.post('/api/categories', addCategory);

module.exports = router;