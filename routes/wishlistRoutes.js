const express = require('express');

const {
  addToWishlist,
  removeFromWishlist,
  getWishlist,
  clearWishlist
} = require('../controllers/wishlistController');

const router = express.Router();

// Get user's wishlist
router.get('/api/wishlist', getWishlist);

// Add activity to wishlist
router.post('/api/wishlist', addToWishlist);

// Remove activity from wishlist
router.delete('/api/wishlist', removeFromWishlist);

// Clear entire wishlist
router.delete('/api/wishlist/clear', clearWishlist);

module.exports = router;