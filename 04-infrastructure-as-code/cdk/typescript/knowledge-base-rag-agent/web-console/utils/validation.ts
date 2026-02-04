/**
 * Input validation and sanitization utilities
 * Protects against XSS and other injection attacks
 */

/**
 * Sanitize user input by removing potentially dangerous HTML/script tags
 * @param input - Raw user input string
 * @returns Sanitized string safe for display
 */
export const sanitizeInput = (input: string): string => {
  if (!input) return '';

  // Remove potentially dangerous HTML tags
  let sanitized = input
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    .replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, '')
    .replace(/<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>/gi, '')
    .replace(/<embed\b[^<]*(?:(?!<\/embed>)<[^<]*)*<\/embed>/gi, '')
    .replace(/<applet\b[^<]*(?:(?!<\/applet>)<[^<]*)*<\/applet>/gi, '')
    .replace(/<meta\b[^<]*(?:(?!<\/meta>)<[^<]*)*<\/meta>/gi, '')
    .replace(/<link\b[^<]*(?:(?!<\/link>)<[^<]*)*<\/link>/gi, '')
    .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, '')
    .trim();

  // Remove javascript: protocol
  sanitized = sanitized.replace(/javascript:/gi, '');

  // Remove on* event handlers
  sanitized = sanitized.replace(/\son\w+\s*=\s*["'][^"']*["']/gi, '');

  return sanitized;
};

/**
 * Validate chat input for length and content
 * @param input - User input to validate
 * @returns Validation result with error message if invalid
 */
export const validateChatInput = (input: string): { valid: boolean; error?: string } => {
  const sanitized = sanitizeInput(input);

  // Check if empty after sanitization
  if (!sanitized || sanitized.trim().length === 0) {
    return { valid: false, error: 'Message cannot be empty' };
  }

  // Check maximum length (4000 characters)
  if (sanitized.length > 4000) {
    return { valid: false, error: 'Message too long (maximum 4000 characters)' };
  }

  // Check for excessive special characters (potential injection attempt)
  const specialCharCount = (sanitized.match(/[^a-zA-Z0-9\s.,!?;:()\-'"]/g) || []).length;
  const specialCharRatio = specialCharCount / sanitized.length;

  if (specialCharRatio > 0.5) {
    return { valid: false, error: 'Message contains too many special characters' };
  }

  // Check for repeated characters (potential spam)
  const repeatedChars = sanitized.match(/(.)\1{10,}/g);
  if (repeatedChars) {
    return { valid: false, error: 'Message contains excessive repeated characters' };
  }

  return { valid: true };
};

/**
 * Validate username input
 * @param username - Username to validate
 * @returns Validation result with error message if invalid
 */
export const validateUsername = (username: string): { valid: boolean; error?: string } => {
  if (!username || username.trim().length === 0) {
    return { valid: false, error: 'Username is required' };
  }

  if (username.length < 3) {
    return { valid: false, error: 'Username must be at least 3 characters' };
  }

  if (username.length > 50) {
    return { valid: false, error: 'Username must be less than 50 characters' };
  }

  // Only allow alphanumeric, underscore, hyphen, and period
  const validPattern = /^[a-zA-Z0-9._-]+$/;
  if (!validPattern.test(username)) {
    return { valid: false, error: 'Username can only contain letters, numbers, dots, underscores, and hyphens' };
  }

  return { valid: true };
};

/**
 * Validate password input
 * @param password - Password to validate
 * @returns Validation result with error message if invalid
 */
export const validatePassword = (password: string): { valid: boolean; error?: string } => {
  if (!password || password.length === 0) {
    return { valid: false, error: 'Password is required' };
  }

  if (password.length < 8) {
    return { valid: false, error: 'Password must be at least 8 characters' };
  }

  if (password.length > 128) {
    return { valid: false, error: 'Password must be less than 128 characters' };
  }

  return { valid: true };
};

/**
 * Sanitize and validate email input
 * @param email - Email to validate
 * @returns Validation result with error message if invalid
 */
export const validateEmail = (email: string): { valid: boolean; error?: string } => {
  if (!email || email.trim().length === 0) {
    return { valid: false, error: 'Email is required' };
  }

  // Basic email validation pattern
  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailPattern.test(email)) {
    return { valid: false, error: 'Invalid email format' };
  }

  if (email.length > 254) {
    return { valid: false, error: 'Email is too long' };
  }

  return { valid: true };
};
