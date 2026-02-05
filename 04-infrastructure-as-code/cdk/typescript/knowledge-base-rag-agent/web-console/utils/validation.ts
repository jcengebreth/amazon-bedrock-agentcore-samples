/**
 * Input validation and sanitization utilities
 * Protects against XSS and other injection attacks
 */

/**
 * List of dangerous URL schemes that should be blocked
 */
const DANGEROUS_SCHEMES = [
  'javascript:',
  'vbscript:',
  'data:',
  'file:',
];

/**
 * List of dangerous HTML tag names
 */
const DANGEROUS_TAGS = [
  'script',
  'iframe',
  'object',
  'embed',
  'applet',
  'meta',
  'link',
  'style',
  'form',
  'input',
  'button',
  'textarea',
  'select',
  'base',
];

/**
 * Sanitize user input by removing potentially dangerous content
 * Uses a tag-stripping approach instead of regex for better security
 * @param input - Raw user input string
 * @returns Sanitized string safe for display
 */
export const sanitizeInput = (input: string): string => {
  if (!input) return '';

  let sanitized = input;

  // Remove dangerous URL schemes (case-insensitive, handles whitespace)
  for (const scheme of DANGEROUS_SCHEMES) {
    // Match scheme with optional whitespace between characters
    const schemePattern = scheme
      .split('')
      .map(char => char === ':' ? '\\s*:' : `\\s*${char}`)
      .join('');
    const regex = new RegExp(schemePattern, 'gi');
    
    let previousLength: number;
    do {
      previousLength = sanitized.length;
      sanitized = sanitized.replace(regex, '');
    } while (sanitized.length !== previousLength);
  }

  // Remove dangerous HTML tags (handles spaces in closing tags like </script >)
  for (const tag of DANGEROUS_TAGS) {
    // Opening tags: <script, <script , <script/
    const openTagRegex = new RegExp(`<\\s*${tag}\\b[^>]*>`, 'gi');
    // Closing tags: </script>, </script >, < /script>
    const closeTagRegex = new RegExp(`<\\s*/\\s*${tag}\\s*>`, 'gi');
    
    let previousLength: number;
    do {
      previousLength = sanitized.length;
      sanitized = sanitized.replace(openTagRegex, '');
      sanitized = sanitized.replace(closeTagRegex, '');
    } while (sanitized.length !== previousLength);
  }

  // Remove content between script tags (in case tags weren't properly closed)
  let previousLength: number;
  do {
    previousLength = sanitized.length;
    // Match script content more broadly
    sanitized = sanitized.replace(/<\s*script[^>]*>[\s\S]*?<\s*\/\s*script\s*>/gi, '');
    sanitized = sanitized.replace(/<\s*style[^>]*>[\s\S]*?<\s*\/\s*style\s*>/gi, '');
  } while (sanitized.length !== previousLength);

  // Remove on* event handlers (onclick, onerror, etc.)
  sanitized = sanitized.replace(/\s+on\w+\s*=\s*["'][^"']*["']/gi, '');
  sanitized = sanitized.replace(/\s+on\w+\s*=\s*[^\s>]+/gi, '');

  return sanitized.trim();
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
