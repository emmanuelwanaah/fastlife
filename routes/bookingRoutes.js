const express = require('express');

const {
  createCheckoutSession,
  confirmBooking,
  getCompletedBookings
} = require('../controllers/bookingController');

const router = express.Router();


// Create Stripe checkout session
router.post(
  '/api/create-checkout-session',
  createCheckoutSession
);


// Confirm booking
router.post(
  '/api/confirm-booking',
  confirmBooking
);


// Get completed bookings
router.get(
  '/api/completed-bookings',
  getCompletedBookings
);


module.exports = router;