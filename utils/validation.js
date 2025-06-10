const { body } = require('express-validator');

// CUID validation function
const isCUID = (value) => {
  // CUID pattern: starts with 'c' followed by 24 alphanumeric characters
  const cuidPattern = /^c[a-z0-9]{24}$/;
  return cuidPattern.test(value);
};

// Custom validator for CUID
const validateCUID = (fieldName, message) => {
  return body(fieldName).custom((value) => {
    if (!value) {
      throw new Error(message || `Valid ${fieldName} is required`);
    }
    if (!isCUID(value)) {
      throw new Error(message || `Valid ${fieldName} is required`);
    }
    return true;
  });
};

// Custom validator for optional CUID
const validateOptionalCUID = (fieldName, message) => {
  return body(fieldName).optional().custom((value) => {
    // Allow empty values (undefined, null, or empty string)
    if (!value || value.trim() === '') return true;
    if (!isCUID(value)) {
      throw new Error(message || `Valid ${fieldName} required if provided`);
    }
    return true;
  });
};

module.exports = {
  isCUID,
  validateCUID,
  validateOptionalCUID
}; 