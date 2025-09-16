// pages/api/tiktok.js
// Env: TIKTOK_ACCESS_TOKEN, TIKTOK_PIXEL_ID

export default async function handler(req, res) {
  // --- CORS ---
  res.setHeader('Access-Control-Allow-Origin', '*'); // for production, replace * with your domain
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(204).end(); // preflight ok
  }
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Only POST allowed' });
  }

  try {
    const ACCESS_TOKEN = process.env.TIKTOK_ACCESS_TOKEN;
    const PIXEL_ID     = process.env.TIKTOK_PIXEL_ID;
    if (!ACCESS_TOKEN || !PIXEL_ID) {
      return res.status(500).json({ error: 'Missing TIKTOK_ACCESS_TOKEN or TIKTOK_PIXEL_ID' });
    }

    const body = req.body || {};
    const nowSec = Math.floor(Date.now() / 1000);

    const isSha256Hex = (s) => typeof s === 'string' && /^[a-f0-9]{64}$/i.test(s);
    const sha256 = async (str) => {
      const norm = (str ?? '').toString().trim().toLowerCase();
      const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(norm));
      return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
    };
    const maybeHash = async (val) => (isSha256Hex(val) ? val : (val ? await sha256(val) : undefined));
