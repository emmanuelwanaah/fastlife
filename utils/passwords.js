const bcrypt = require('bcrypt');

/**
 * Validate and hash a password securely
 * @param {string} newPassword - The new password input
 * @param {string|null} oldHash - The existing hashed password (optional, e.g. in reset)
 * @returns {Promise<{ success: boolean, message?: string, hash?: string }> }
 */
async function validateAndHashPassword(newPassword, oldHash = null) {
  // Updated: No special character required
  const strongPasswordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{8,}$/;

  if (!strongPasswordRegex.test(newPassword)) {
    return {
      success: false,
      message: "Password must be at least 8 characters long and include uppercase, lowercase, and a number.",
    };
  }

  // Optional: prevent reuse of the same password
  if (oldHash) {
    const isSame = await bcrypt.compare(newPassword, oldHash);
    if (isSame) {
      return { success: false, message: "You cannot reuse your old password." };
    }
  }

  const hash = await bcrypt.hash(newPassword, 10);
  return { success: true, hash };
}

module.exports = { validateAndHashPassword };
