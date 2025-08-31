// // utils/email.js (SMTP Setup & Mailer)
// const nodemailer = require('nodemailer');

// const transporter = nodemailer.createTransport({
//   service: 'gmail',
//   auth: {
//     user: 'wanaahmanuel@gmail.com', // Use env in real projects
//     pass: 'qsju nlqu tasr pdld',
//   },
// });

// async function sendVerificationCode(email, code) {
//   const mailOptions = {
//     from: '"FastLifeTravel" <wanaahmanuel@gmail.com>',
//     to: email,
//     subject: 'Password Reset Verification Code',
//     html: `<p>Your password reset code is: <b>${code}</b></p>`,
//   };
//   await transporter.sendMail(mailOptions);
// }

// module.exports = { sendVerificationCode };
// utils/email.js
const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  host: "smtp-relay.brevo.com",   // Brevo SMTP host
  port: 587,                      // TLS port
  secure: false,                  // STARTTLS (not SSL)
  auth: {
    user: process.env.BREVO_USER,     // Brevo login (SMTP email)
    pass: process.env.BREVO_SMTP_KEY, // Brevo SMTP key
  },
});

async function sendVerificationCode(email, code) {
  const mailOptions = {
    from: '"FastLifeTravel" <no-reply@fastlifetraveltour.com>', 
    to: email,
    subject: "Password Reset Verification Code",
    html: `<p>Your password reset code is: <b>${code}</b></p>`,
  };

  return transporter.sendMail(mailOptions);
}

module.exports = { sendVerificationCode };
