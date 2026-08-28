const express = require('express');

const {
  getExplore,
  getExploreById,
  addExperience
} = require('../controllers/exploreController');

const router = express.Router();

// Get all explore items
router.get('/api/explore', getExplore);

// Get single explore item
router.get('/api/explore/:id', getExploreById);

// Add experience
router.post('/api/experiences', addExperience);

module.exports = router;