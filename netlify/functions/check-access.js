// ============================================
// CHECK ACCESS - With caching to avoid rate limits
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

// In-memory cache
let walletCache = {
  wallets: new Set(),
  lastFetch: 0,
  ttl: 5 * 60 * 1000 // 5 minutes
};

exports.handler = async (event) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Content-Type': 'application/json'
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
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
    // Check if cache is still valid
    const now = Date.now();
    if (walletCache.wallets.size === 0 || (now - walletCache.lastFetch) > walletCache.ttl) {
      // Fetch fresh data from Google Sheets
      await refreshCache();
    }

    // Check if wallet exists in cached set (case-insensitive)
    const walletLower = wallet.toLowerCase();
    const hasAccess = walletCache.wallets.has(walletLower);

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ hasAccess })
    };

  } catch (error) {
    console.error('Error:', error);
    
    // If we have cached data and API fails, use stale cache
    if (walletCache.wallets.size > 0) {
      const walletLower = wallet.toLowerCase();
      const hasAccess = walletCache.wallets.has(walletLower);
      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({ hasAccess, cached: true })
      };
    }
    
    return { 
      statusCode: 500, 
      headers, 
      body: JSON.stringify({ error: 'Server error - please try again', hasAccess: false }) 
    };
  }
};

async function refreshCache() {
  console.log('Refreshing wallet cache from Google Sheets...');
  
  const accessToken = await getGoogleToken();
  
  // Fetch AccessList tab - Column A contains wallet addresses
  const sheetUrl = `https://sheets.googleapis.com/v4/spreadsheets/${SPREADSHEET_ID}/values/AccessList!A:A`;
  const response = await fetch(sheetUrl, {
    headers: { 'Authorization': `Bearer ${accessToken}` }
  });

  if (!response.ok) {
    const errorText = await response.text();
    console.error('Sheet API error:', response.status, errorText);
    throw new Error('Failed to read sheet');
  }

  const data = await response.json();
  const rows = data.values || [];

  // Build a Set for O(1) lookups (skip header row if present)
  const newWallets = new Set();
  for (const row of rows) {
    if (row[0] && row[0].startsWith('0x')) {
      newWallets.add(row[0].toLowerCase());
    }
  }

  walletCache.wallets = newWallets;
  walletCache.lastFetch = Date.now();
  
  console.log(`Cache refreshed: ${newWallets.size} wallets loaded`);
}

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
