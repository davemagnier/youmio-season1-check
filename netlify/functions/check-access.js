// ============================================
// CHECK ACCESS - Checks if wallet is on Season 1 allowlist
// File: netlify/functions/check-access.js
// ============================================

const crypto = require('crypto');

let GOOGLE_SERVICE_ACCOUNT_EMAIL;
let GOOGLE_PRIVATE_KEY;

try {
  const serviceAccount = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_KEY || '{}');
  GOOGLE_SERVICE_ACCOUNT_EMAIL = serviceAccount.client_email;
  GOOGLE_PRIVATE_KEY = serviceAccount.private_key;
} catch (e) {}

const SPREADSHEET_ID = process.env.GOOGLE_SPREADSHEET_ID;

// Simple rate limiting
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX = 30; // 30 requests per minute

function isRateLimited(ip) {
  const now = Date.now();
  const record = rateLimitMap.get(ip);
  if (!record || now - record.timestamp > RATE_LIMIT_WINDOW) {
    rateLimitMap.set(ip, { timestamp: now, count: 1 });
    return false;
  }
  record.count++;
  return record.count > RATE_LIMIT_MAX;
}

exports.handler = async (event) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Type': 'application/json'
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
  }

  // Rate limiting
  const clientIP = event.headers['x-forwarded-for'] || 'unknown';
  if (isRateLimited(clientIP)) {
    return { 
      statusCode: 429, 
      headers, 
      body: JSON.stringify({ error: 'Too many requests. Please wait a minute.' }) 
    };
  }

  if (event.httpMethod !== 'GET') {
    return { statusCode: 405, headers, body: JSON.stringify({ error: 'Method not allowed' }) };
  }

  const wallet = event.queryStringParameters?.wallet;

  if (!wallet) {
    return { statusCode: 400, headers, body: JSON.stringify({ error: 'Missing wallet', hasAccess: false }) };
  }

  if (!/^0x[a-fA-F0-9]{40}$/.test(wallet)) {
    return { statusCode: 400, headers, body: JSON.stringify({ error: 'Invalid wallet', hasAccess: false }) };
  }

  try {
    const accessToken = await getGoogleToken();
    
    // Check AccessList tab - Column A contains wallet addresses
    const sheetUrl = `https://sheets.googleapis.com/v4/spreadsheets/${SPREADSHEET_ID}/values/AccessList!A:A`;
    const response = await fetch(sheetUrl, {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });

    if (!response.ok) {
      throw new Error('Failed to read sheet');
    }

    const data = await response.json();
    const rows = data.values || [];

    // Check if wallet exists in the list (case-insensitive)
    const walletLower = wallet.toLowerCase();
    const hasAccess = rows.some(row => row[0] && row[0].toLowerCase() === walletLower);

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ hasAccess })
    };

  } catch (error) {
    console.error('Error:', error);
    return { 
      statusCode: 500, 
      headers, 
      body: JSON.stringify({ error: 'Server error', hasAccess: false }) 
    };
  }
};

async function getGoogleToken() {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT' };
  const payload = {
    iss: GOOGLE_SERVICE_ACCOUNT_EMAIL,
    scope: 'https://www.googleapis.com/auth/spreadsheets.readonly',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600
  };
  
  const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signingInput = `${headerB64}.${payloadB64}`;
  
  const sign = crypto.createSign('RSA-SHA256');
  sign.update(signingInput);
  const signature = sign.sign(GOOGLE_PRIVATE_KEY, 'base64url');
  
  const jwt = `${signingInput}.${signature}`;
  
  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`
  });
  
  const data = await response.json();
  if (!data.access_token) throw new Error('No access token');
  return data.access_token;
}
