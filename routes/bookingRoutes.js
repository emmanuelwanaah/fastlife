const express = require('express');

const {
    createCheckoutSession,
    confirmBooking,
    getCompletedBookings
} = require('../controllers/bookingController');

const router = express.Router();


// ============================================================
// CREATE STRIPE CHECKOUT SESSION
// ============================================================

router.post(
    '/api/create-checkout-session',
    createCheckoutSession
);


// ============================================================
// CONFIRM BOOKING AFTER STRIPE PAYMENT
// ============================================================

router.post(
    '/api/confirm-booking',
    confirmBooking
);


// ============================================================
// GET COMPLETED BOOKINGS
// ============================================================

router.get(
    '/api/completed-bookings',
    getCompletedBookings
);


module.exports = router;