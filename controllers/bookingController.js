const db = require('../config/database');
const stripe = require('stripe')(process.env.STRIPE_SECRET);


// ========================================
// GENERATE BOOKING REFERENCE
// ========================================

const generateBookingRef = () => {
  return 'REF' + Math.floor(
    100000000 + Math.random() * 900000000
  );
};


// ========================================
// CREATE STRIPE CHECKOUT SESSION
// ========================================

const createCheckoutSession = async (req, res) => {
  try {
    const userId = req.session.userId;

    if (!userId) {
      return res.status(401).json({
        error: 'Unauthorized'
      });
    }

    const {
      date,
      time,
      numberOfPersons,
      total,
      activities
    } = req.body;

    // Validate required fields
    if (
      !Array.isArray(activities) ||
      activities.length === 0 ||
      !total ||
      !date ||
      !time ||
      !numberOfPersons
    ) {
      return res.status(400).json({
        error: 'Invalid booking data'
      });
    }

    // Prepare Stripe line items
    const lineItems = activities.map((act) => ({
      price_data: {
        currency: 'eur',

        product_data: {
          name: act.title,

          images: [act.image],

          description: `${act.location} | ${date} @ ${time} | ${numberOfPersons} person${
            numberOfPersons > 1 ? 's' : ''
          }`
        },

        unit_amount: Math.round(
          Number(act.price) * 100
        )
      },

      quantity: numberOfPersons
    }));


    // Create Stripe checkout session
    const checkoutSession =
      await stripe.checkout.sessions.create({
        payment_method_types: ['card'],

        mode: 'payment',

        line_items: lineItems,

        success_url:
          'https://www.fastlifetraveltour.com/completedbookings.html',

        cancel_url:
          'https://www.fastlifetraveltour.com/bookings.html',

        metadata: {
          userId: userId.toString(),
          date,
          time,
          numberOfPersons: numberOfPersons.toString(),
          total: total.toString()
        }
      });


    res.json({
      id: checkoutSession.id
    });

  } catch (error) {
    console.error(
      '❌ Error creating Stripe session:',
      error
    );

    res.status(500).json({
      error: 'Internal Server Error'
    });
  }
};


// ========================================
// CONFIRM BOOKING
// ========================================

const confirmBooking = async (req, res) => {
  const userId = req.session.userId;

  const {
    reference,
    date,
    time,
    numberOfPersons,
    total,
    activities
  } = req.body;


  if (
    !userId ||
    !reference ||
    !activities ||
    !Array.isArray(activities)
  ) {
    return res.status(400).json({
      success: false,
      message: 'Invalid booking data.'
    });
  }


  try {
    const now = new Date();


    for (const activity of activities) {

      if (
        !activity?.id ||
        isNaN(activity.price)
      ) {
        console.warn(
          '⚠️ Skipping invalid activity:',
          activity
        );

        continue;
      }


      // Price per booking
      const pricePerBooking =
        parseFloat(activity.price) *
        numberOfPersons;


      await db.execute(
        `
        INSERT INTO bookings (
          user_id,
          activity_id,
          booking_reference,
          total_price,
          created_at,
          payment_status,
          status,
          booking_date,
          time_selected,
          number_of_persons
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `,
        [
          userId,
          activity.id,
          reference,
          parseFloat(activity.totalPrice),
          now,
          'paid',
          'confirmed',
          date,
          time,
          numberOfPersons
        ]
      );


      // Remove activity from wishlist
      await db.execute(
        `
        DELETE FROM wishlist
        WHERE user_id = ?
        AND activity_id = ?
        `,
        [
          userId,
          activity.id
        ]
      );
    }


    res.json({
      success: true
    });

  } catch (err) {

    console.error(
      '❌ Failed to insert booking:',
      err.message
    );

    res.status(500).json({
      success: false,
      message: 'Database error'
    });
  }
};


// ========================================
// GET COMPLETED BOOKINGS
// ========================================

const getCompletedBookings = async (req, res) => {

  const userId = req.session.userId;

  if (!userId) {
    return res.status(401).json({
      error: 'Unauthorized'
    });
  }


  try {

    const [bookings] = await db.query(
      `
      SELECT
        b.booking_reference AS reference,
        a.title,
        a.image_url AS image,
        a.location,
        b.booking_date,
        b.time_selected,
        b.number_of_persons,
        b.total_price AS price
      FROM bookings b
      JOIN activities a
        ON b.activity_id = a.id
      WHERE b.user_id = ?
      ORDER BY b.created_at DESC
      `,
      [userId]
    );


    res.json({
      bookings
    });

  } catch (err) {

    console.error(
      'Error fetching completed bookings:',
      err
    );

    res.status(500).json({
      error: 'Failed to load bookings'
    });
  }
};


module.exports = {
  generateBookingRef,
  createCheckoutSession,
  confirmBooking,
  getCompletedBookings
};