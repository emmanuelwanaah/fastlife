// utils/email.js (SMTP Setup & Mailer)
const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'wanaahmanuel@gmail.com', // Use env in real projects
    pass: 'qsju nlqu tasr pdld',
  },
});

async function sendVerificationCode(email, code) {
  const mailOptions = {
    from: '"FastLifeTravel" <wanaahmanuel@gmail.com>',
    to: email,
    subject: 'Password Reset Verification Code',
    html: `<p>Your password reset code is: <b>${code}</b></p>`,
  };
  await transporter.sendMail(mailOptions);
}

module.exports = { sendVerificationCode };
