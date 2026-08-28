const express = require('express');

const {
  getActivities,
  getActivityById,
  addActivity
} = require('../controllers/activityController');

const router = express.Router();

// ========================================
// GET ALL ACTIVITIES
// GET /api/activities
// ========================================
router.get('/', getActivities);

// ========================================
// GET SINGLE ACTIVITY
// GET /api/activities/:id
// ========================================
router.get('/:id', getActivityById);

// ========================================
// ADD ACTIVITY
// POST /api/activities
// ========================================
router.post('/', addActivity);

module.exports = router;