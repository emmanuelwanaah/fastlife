const db = require('../config/database');
const stripe = require('stripe')(process.env.STRIPE_SECRET);


// ============================================================
// GENERATE BOOKING REFERENCE
// ============================================================

const generateBookingRef = () => {
    return 'REF' + Math.floor(
        100000000 + Math.random() * 900000000
    );
};


// ============================================================
// CREATE STRIPE CHECKOUT SESSION
// ============================================================

const createCheckoutSession = async (req, res) => {

    try {

        const userId = req.session.userId;

        if (!userId) {
            return res.status(401).json({
                success: false,
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


        // --------------------------------------------------------
        // VALIDATION
        // --------------------------------------------------------

        if (
            !Array.isArray(activities) ||
            activities.length === 0 ||
            !date ||
            !time ||
            !numberOfPersons
        ) {
            return res.status(400).json({
                success: false,
                error: 'Invalid booking data'
            });
        }


        const persons = Number(numberOfPersons);

        if (!Number.isInteger(persons) || persons < 1) {
            return res.status(400).json({
                success: false,
                error: 'Invalid number of persons'
            });
        }


        // --------------------------------------------------------
        // PREPARE STRIPE LINE ITEMS
        // --------------------------------------------------------

        const lineItems = activities.map((activity) => {

            const price = Number(activity.price);

            if (
                !activity.id ||
                !activity.title ||
                !Number.isFinite(price) ||
                price < 0
            ) {
                throw new Error(
                    'Invalid activity data'
                );
            }


            return {
                price_data: {

                    currency: 'eur',

                    product_data: {
                        name: activity.title,

                        ...(activity.image
                            ? {
                                images: [activity.image]
                            }
                            : {}
                        ),

                        description:
                            `${activity.location || ''} | ` +
                            `${date} @ ${time} | ` +
                            `${persons} person${persons > 1 ? 's' : ''}`
                    },

                    unit_amount: Math.round(
                        price * 100
                    )
                },

                quantity: persons
            };

        });


        // --------------------------------------------------------
        // GENERATE REFERENCE
        // --------------------------------------------------------

        const reference = generateBookingRef();


        // --------------------------------------------------------
        // CREATE STRIPE CHECKOUT SESSION
        // --------------------------------------------------------

        const checkoutSession =
            await stripe.checkout.sessions.create({

                payment_method_types: ['card'],

                mode: 'payment',

                line_items: lineItems,


                // IMPORTANT:
                // Stripe replaces {CHECKOUT_SESSION_ID}
                // with the real session ID after payment.

                success_url:
                    'https://www.fastlifetraveltour.com/completedbookings.html?session_id={CHECKOUT_SESSION_ID}',

                cancel_url:
                    'https://www.fastlifetraveltour.com/bookings.html',


                metadata: {

                    userId:
                        userId.toString(),

                    reference,

                    date,

                    time,

                    numberOfPersons:
                        persons.toString(),

                    total:
                        total !== undefined
                            ? total.toString()
                            : '0',

                    // Store activity IDs as well
                    activityIds:
                        activities
                            .map(activity => activity.id)
                            .join(',')
                }

            });


        // --------------------------------------------------------
        // RETURN SESSION ID TO FRONTEND
        // --------------------------------------------------------

        return res.json({

            success: true,

            id: checkoutSession.id,

            sessionId:
                checkoutSession.id,

            reference

        });


    } catch (error) {

        console.error(
            '❌ Error creating Stripe session:',
            error
        );

        return res.status(500).json({
            success: false,
            error: 'Internal Server Error'
        });

    }

};


const confirmBooking = async (req, res) => {

    try {

        const userId = req.session.userId;

        if (!userId) {
            return res.status(401).json({
                success: false,
                message: 'Unauthorized'
            });
        }


        const {
            sessionId,
            activities,
            date,
            time,
            numberOfPersons
        } = req.body;


        // --------------------------------------------------------
        // VALIDATE SESSION ID
        // --------------------------------------------------------

        if (!sessionId) {

            return res.status(400).json({
                success: false,
                message:
                    'Stripe Checkout Session ID is required.'
            });

        }


        // --------------------------------------------------------
        // RETRIEVE SESSION FROM STRIPE
        // --------------------------------------------------------

        const checkoutSession =
            await stripe.checkout.sessions.retrieve(
                sessionId
            );


        // --------------------------------------------------------
        // MAKE SURE SESSION BELONGS TO THIS USER
        // --------------------------------------------------------

        if (
            checkoutSession.metadata?.userId !==
            userId.toString()
        ) {

            console.warn(
                '⚠️ Stripe session user mismatch'
            );

            return res.status(403).json({
                success: false,
                message:
                    'This payment session does not belong to you.'
            });

        }


        // --------------------------------------------------------
        // CHECK PAYMENT STATUS
        // --------------------------------------------------------

        if (
            checkoutSession.payment_status !==
            'paid'
        ) {

            console.warn(
                '⚠️ Payment not completed:',
                checkoutSession.payment_status
            );

            return res.status(400).json({

                success: false,

                message:
                    'Payment has not been completed.'
            });

        }


        // --------------------------------------------------------
        // GET TRUSTED DATA FROM STRIPE METADATA
        // --------------------------------------------------------

        const stripeMetadata =
            checkoutSession.metadata || {};


        const reference =
            stripeMetadata.reference;


        const bookingDate =
            stripeMetadata.date || date;


        const bookingTime =
            stripeMetadata.time || time;


        const persons =
            Number(
                stripeMetadata.numberOfPersons ||
                numberOfPersons
            );


        if (!reference) {

            return res.status(400).json({
                success: false,
                message:
                    'Booking reference is missing from Stripe session.'
            });

        }


        if (
            !Number.isInteger(persons) ||
            persons < 1
        ) {

            return res.status(400).json({
                success: false,
                message:
                    'Invalid number of persons.'
            });

        }


        // --------------------------------------------------------
        // CHECK IF BOOKING WAS ALREADY SAVED
        // --------------------------------------------------------
        //
        // This prevents refreshing completedbookings.html
        // from creating duplicate bookings.
        //
        // --------------------------------------------------------

        const [existingBookings] =
            await db.execute(

                `
                SELECT id
                FROM bookings
                WHERE booking_reference = ?
                LIMIT 1
                `,

                [reference]

            );


        if (existingBookings.length > 0) {

            console.log(
                'ℹ️ Booking already exists:',
                reference
            );

            return res.json({

                success: true,

                alreadyExists: true,

                reference

            });

        }


        // --------------------------------------------------------
        // GET ACTIVITIES
        // --------------------------------------------------------

        let bookingActivities =
            activities;


        // If frontend didn't send activities,
        // use the IDs stored in Stripe metadata.

        if (
            !Array.isArray(bookingActivities) ||
            bookingActivities.length === 0
        ) {

            const activityIds =
                stripeMetadata.activityIds
                    ? stripeMetadata.activityIds
                        .split(',')
                        .map(id => Number(id))
                        .filter(id => Number.isInteger(id))
                    : [];


            if (activityIds.length === 0) {

                return res.status(400).json({

                    success: false,

                    message:
                        'No activities found for this payment.'
                });

            }


            const placeholders =
                activityIds
                    .map(() => '?')
                    .join(',');


            const [rows] =
                await db.execute(

                    `
                    SELECT
                        id,
                        title,
                        price
                    FROM activities
                    WHERE id IN (${placeholders})
                    `,

                    activityIds

                );


            bookingActivities =
                rows.map(activity => ({

                    id: activity.id,

                    title: activity.title,

                    price:
                        Number(activity.price),

                    totalPrice:
                        Number(activity.price) *
                        persons

                }));

        }


        if (
            !Array.isArray(bookingActivities) ||
            bookingActivities.length === 0
        ) {

            return res.status(400).json({

                success: false,

                message:
                    'No activities found for this booking.'
            });

        }


        // --------------------------------------------------------
        // USE STRIPE'S ACTUAL AMOUNT PAID
        // --------------------------------------------------------

        const stripeTotal =
            (
                Number(
                    checkoutSession.amount_total
                ) / 100
            );


        console.log(
            '💳 Stripe payment verified:',
            {
                sessionId,
                paymentStatus:
                    checkoutSession.payment_status,
                amountPaid:
                    stripeTotal,
                reference
            }
        );


        // --------------------------------------------------------
        // INSERT BOOKINGS
        // --------------------------------------------------------

        const connection =
            await db.getConnection();

        try {

            await connection.beginTransaction();


            for (
                const activity
                of bookingActivities
            ) {

                if (!activity?.id) {

                    console.warn(
                        '⚠️ Skipping invalid activity:',
                        activity
                    );

                    continue;
                }


                // ------------------------------------------------
                // GET REAL ACTIVITY PRICE FROM DATABASE
                // ------------------------------------------------
                //
                // Do not trust the price sent by browser.
                //
                // ------------------------------------------------

                const [activityRows] =
                    await connection.execute(

                        `
                        SELECT
                            id,
                            price
                        FROM activities
                        WHERE id = ?
                        LIMIT 1
                        `,

                        [activity.id]

                    );


                if (
                    activityRows.length === 0
                ) {

                    console.warn(
                        '⚠️ Activity not found:',
                        activity.id
                    );

                    continue;

                }


                const realPrice =
                    Number(
                        activityRows[0].price
                    );


                const activityTotal =
                    realPrice * persons;


                // ------------------------------------------------
                // INSERT BOOKING
                // ------------------------------------------------

                await connection.execute(

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

                        activityTotal,

                        new Date(),

                        'paid',

                        'confirmed',

                        bookingDate,

                        bookingTime,

                        persons

                    ]

                );


                // ------------------------------------------------
                // REMOVE FROM WISHLIST
                // ------------------------------------------------

                await connection.execute(

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


            await connection.commit();


            console.log(
                '✅ Booking saved successfully:',
                reference
            );


            return res.json({

                success: true,

                reference,

                paymentStatus:
                    checkoutSession.payment_status,

                amountPaid:
                    stripeTotal

            });


        } catch (databaseError) {

            await connection.rollback();

            throw databaseError;

        } finally {

            connection.release();

        }


    } catch (error) {

        console.error(
            '❌ Failed to confirm booking:',
            error
        );

        return res.status(500).json({

            success: false,

            message:
                'Unable to confirm booking.'

        });

    }

};



// ============================================================
// GET COMPLETED BOOKINGS
// ============================================================

const getCompletedBookings = async (req, res) => {

    const userId =
        req.session.userId;


    if (!userId) {

        return res.status(401).json({

            success: false,

            error: 'Unauthorized'

        });

    }


    try {

        const [bookings] =
            await db.query(

                `
                SELECT

                    b.booking_reference AS reference,

                    a.title,

                    a.image_url AS image,

                    a.location,

                    b.booking_date,

                    b.time_selected,

                    b.number_of_persons,

                    b.total_price AS price,

                    b.payment_status,

                    b.status

                FROM bookings b

                JOIN activities a
                    ON b.activity_id = a.id

                WHERE b.user_id = ?

                AND b.payment_status = 'paid'

                AND b.status = 'confirmed'

                ORDER BY b.created_at DESC
                `,

                [userId]

            );


        return res.json({

            success: true,

            bookings

        });


    } catch (error) {

        console.error(
            '❌ Error fetching completed bookings:',
            error
        );

        return res.status(500).json({

            success: false,

            error:
                'Failed to load bookings'

        });

    }

};



// ============================================================
// EXPORTS
// ============================================================

module.exports = {

    generateBookingRef,

    createCheckoutSession,

    confirmBooking,

    getCompletedBookings

};