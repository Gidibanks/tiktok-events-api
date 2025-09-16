// pages/api/tiktok.js
// Server-side TikTok Events API relay (production)
// Env vars required: TIKTOK_ACCESS_TOKEN, TIKTOK_PIXEL_ID

export default async function handler(req, res) {
  // CORS (browser → your API). For production, consider locking to your domains.
  res.setHeader('Access-Control-Allow-Origin', '*'); // e.g. replace '*' with 'https://ogaviral.com'
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Only POST allowed' });

  try {
    const ACCESS_TOKEN = process.env.TIKTOK_ACCESS_TOKEN;
    const PIXEL_ID     = process.env.TIKTOK_PIXEL_ID;
    if (!ACCESS_TOKEN || !PIXEL_ID) {
      return res.status(500).json({ error: 'Missing TIKTOK_ACCESS_TOKEN or TIKTOK_PIXEL_ID' });
    }

    const body = req.body || {};
    const nowSec = Math.floor(Date.now() / 1000);

    // Helpers
    const isSha256Hex = (s) => typeof s === 'string' && /^[a-f0-9]{64}$/i.test(s);
    const sha256 = async (str) => {
      const norm = (str ?? '').toString().trim().toLowerCase();
      const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(norm));
      return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
    };
    const maybeHash = async (val) => (isSha256Hex(val) ? val : (val ? await sha256(val) : undefined));

    // User identifiers (send raw; we’ll hash if needed)
    const uIn = body.user || {};
    const user = {
      email:        await maybeHash(uIn.email),        // raw OK; will hash
      phone_number: await maybeHash(uIn.phone_number), // must be E.164 before hashing if raw (e.g., 2348123…)
      external_id:  await maybeHash(uIn.external_id),
      _ttp:         uIn._ttp,     // TikTok first-party cookie (if present)
      ttclid:       uIn.ttclid    // TikTok click id (if present)
    };

    // Network signals (help TikTok match)
    const clientIp  = (req.headers['x-forwarded-for'] || '').split(',')[0] || req.socket?.remoteAddress;
    const userAgent = req.headers['user-agent'];

    const dataObj = {
      event:      body.event || 'CompleteRegistration', // e.g., Purchase, AddToCart, CompleteRegistration
      event_time: Number(body.event_time) || nowSec,    // seconds
      user,
      page:       body.page,
      ip:         body.ip || clientIp,
      user_agent: body.user_agent || userAgent,
      properties: body.properties
    };

    const payload = {
      event_source: 'web',
      event_source_id: PIXEL_ID,
      data: [dataObj]
    };

    const resp = await fetch('https://business-api.tiktok.com/open_api/v1.3/event/track/', {
      method: 'POST',
      headers: {
        'Access-Token': ACCESS_TOKEN,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });

    const out = await resp.json();
    return res.status(resp.ok ? 200 : resp.status).json(out);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Server error', details: String(e) });
  }
}
