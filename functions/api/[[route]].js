/**
 * SOC API — Cloudflare Pages Function (catch-all route)
 * Handles all /api/* requests
 *
 * Endpoints:
 *   POST /api/auth/login        — Login with employee_id + pin
 *   GET  /api/stores            — List all active stores
 *   POST /api/inspections       — Submit a new inspection
 *   GET  /api/inspections       — List inspections (filter by store, date)
 *   GET  /api/inspections/:id   — Get single inspection with items
 *   GET  /api/dashboard         — Management dashboard data
 *   GET  /api/users             — List users (GM only)
 *   POST /api/users             — Create user (GM only)
 */

// ── CORS Headers ──────────────────────────────────────────────
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS },
  });
}

function errorResponse(message, status = 400) {
  return jsonResponse({ error: message }, status);
}

// ── Simple JWT (HMAC-SHA256) ──────────────────────────────────
async function createToken(payload, secret) {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = btoa(JSON.stringify({ ...payload, exp: Date.now() + 24 * 60 * 60 * 1000 }));
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(`${header}.${body}`));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)));
  return `${header}.${body}.${sigB64}`;
}

async function verifyToken(token, secret) {
  try {
    const [header, body, sig] = token.split('.');
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const sigBytes = Uint8Array.from(atob(sig), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, enc.encode(`${header}.${body}`));
    if (!valid) return null;
    const payload = JSON.parse(atob(body));
    if (payload.exp < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

const JWT_SECRET = 'soc-supersports-secret-2026';

async function authenticate(request) {
  const auth = request.headers.get('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) return null;
  return verifyToken(auth.slice(7), JWT_SECRET);
}

// ── Main Handler ──────────────────────────────────────────────
export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: CORS_HEADERS });
  }

  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;
  const DB = env.DB;

  if (!DB) {
    return errorResponse('Database not configured. Add D1 binding in Cloudflare dashboard.', 500);
  }

  try {
    // ── Auth ─────────────────────────────────────────────
    if (path === '/api/auth/login' && method === 'POST') {
      const { employee_id, pin } = await request.json();
      if (!employee_id || !pin) return errorResponse('employee_id and pin required');

      const user = await DB.prepare(
        'SELECT id, employee_id, name, role, store_name FROM users WHERE employee_id = ? AND pin = ?'
      ).bind(employee_id, pin).first();

      if (!user) return errorResponse('Invalid credentials', 401);

      const token = await createToken(
        { id: user.id, employee_id: user.employee_id, name: user.name, role: user.role, store_name: user.store_name },
        JWT_SECRET
      );
      return jsonResponse({ token, user });
    }

    // ── Stores (public) ─────────────────────────────────
    if (path === '/api/stores' && method === 'GET') {
      const { results } = await DB.prepare(
        'SELECT id, name, brand, region, district FROM stores WHERE active = 1 ORDER BY brand, name'
      ).all();
      return jsonResponse({ stores: results });
    }

    // ── Protected routes ────────────────────────────────
    const user = await authenticate(request);
    if (!user) return errorResponse('Unauthorized', 401);

    // ── Submit Inspection ───────────────────────────────
    if (path === '/api/inspections' && method === 'POST') {
      const data = await request.json();
      const { store_name, date, overall_score, total_items, passed_items, categories_scores, ai_summary, items } = data;

      if (!store_name || !date) return errorResponse('store_name and date required');

      const result = await DB.prepare(
        `INSERT INTO inspections (store_name, inspector_name, inspector_id, date, overall_score, total_items, passed_items, status, categories_scores, ai_summary)
         VALUES (?, ?, ?, ?, ?, ?, ?, 'completed', ?, ?)`
      ).bind(
        store_name, user.name, user.employee_id, date,
        overall_score || 0, total_items || 0, passed_items || 0,
        JSON.stringify(categories_scores || {}), ai_summary || ''
      ).run();

      const inspectionId = result.meta.last_row_id;

      if (items && items.length > 0) {
        const stmt = DB.prepare(
          `INSERT INTO inspection_items (inspection_id, category_id, category_name, item_index, item_text, status, photo_data)
           VALUES (?, ?, ?, ?, ?, ?, ?)`
        );
        const batch = items.map(item =>
          stmt.bind(inspectionId, item.category_id, item.category_name, item.item_index, item.item_text, item.status || 'unchecked', item.photo_data || null)
        );
        await DB.batch(batch);
      }

      return jsonResponse({ id: inspectionId, message: 'Inspection saved' }, 201);
    }

    // ── List Inspections ────────────────────────────────
    if (path === '/api/inspections' && method === 'GET') {
      const store = url.searchParams.get('store');
      const date = url.searchParams.get('date');
      const limit = parseInt(url.searchParams.get('limit') || '50');

      let query = 'SELECT id, store_name, inspector_name, date, overall_score, total_items, passed_items, status, created_at FROM inspections WHERE 1=1';
      const params = [];

      if (user.role === 'SM' && user.store_name) {
        query += ' AND store_name = ?';
        params.push(user.store_name);
      } else if (store) {
        query += ' AND store_name = ?';
        params.push(store);
      }
      if (date) {
        query += ' AND date = ?';
        params.push(date);
      }

      query += ' ORDER BY created_at DESC LIMIT ?';
      params.push(limit);

      const { results } = await DB.prepare(query).bind(...params).all();
      return jsonResponse({ inspections: results });
    }

    // ── Get Single Inspection ───────────────────────────
    const inspMatch = path.match(/^\/api\/inspections\/(\d+)$/);
    if (inspMatch && method === 'GET') {
      const id = inspMatch[1];
      const inspection = await DB.prepare('SELECT * FROM inspections WHERE id = ?').bind(id).first();
      if (!inspection) return errorResponse('Not found', 404);

      const { results: items } = await DB.prepare(
        'SELECT id, category_id, category_name, item_index, item_text, status FROM inspection_items WHERE inspection_id = ? ORDER BY category_id, item_index'
      ).bind(id).all();

      return jsonResponse({ inspection, items });
    }

    // ── Dashboard ───────────────────────────────────────
    if (path === '/api/dashboard' && method === 'GET') {
      const date = url.searchParams.get('date') || new Date().toISOString().split('T')[0];
      const month = date.substring(0, 7);

      const { results: todayInspections } = await DB.prepare(
        `SELECT store_name, inspector_name, overall_score, total_items, passed_items, created_at
         FROM inspections WHERE date = ? ORDER BY created_at DESC`
      ).bind(date).all();

      const { results: monthSummary } = await DB.prepare(
        `SELECT store_name, COUNT(*) as inspection_count,
                ROUND(AVG(overall_score), 1) as avg_score,
                MIN(overall_score) as min_score, MAX(overall_score) as max_score
         FROM inspections WHERE date LIKE ? || '%'
         GROUP BY store_name ORDER BY avg_score DESC`
      ).bind(month).all();

      const { results: allStores } = await DB.prepare('SELECT name FROM stores WHERE active = 1').all();
      const inspectedToday = new Set(todayInspections.map(i => i.store_name));
      const missingStores = allStores.map(s => s.name).filter(name => !inspectedToday.has(name));

      const { results: overallStats } = await DB.prepare(
        `SELECT COUNT(*) as total_inspections, ROUND(AVG(overall_score), 1) as avg_score,
                COUNT(DISTINCT store_name) as stores_inspected
         FROM inspections WHERE date LIKE ? || '%'`
      ).bind(month).all();

      return jsonResponse({
        date, month,
        today: { inspections: todayInspections, count: todayInspections.length, missing_stores: missingStores },
        month_summary: monthSummary,
        overall: overallStats[0] || {},
      });
    }

    // ── Users (GM only) ─────────────────────────────────
    if (path === '/api/users' && method === 'GET') {
      if (user.role !== 'GM') return errorResponse('Forbidden', 403);
      const { results } = await DB.prepare(
        'SELECT id, employee_id, name, role, store_name, created_at FROM users ORDER BY role, name'
      ).all();
      return jsonResponse({ users: results });
    }

    if (path === '/api/users' && method === 'POST') {
      if (user.role !== 'GM') return errorResponse('Forbidden', 403);
      const { employee_id, name, pin, role, store_name } = await request.json();
      if (!employee_id || !name || !pin) return errorResponse('employee_id, name, and pin required');

      try {
        await DB.prepare(
          'INSERT INTO users (employee_id, name, pin, role, store_name) VALUES (?, ?, ?, ?, ?)'
        ).bind(employee_id, name, pin, role || 'SM', store_name || null).run();
        return jsonResponse({ message: 'User created' }, 201);
      } catch (err) {
        if (err.message.includes('UNIQUE')) return errorResponse('Employee ID already exists', 409);
        throw err;
      }
    }

    return errorResponse('Not found', 404);

  } catch (err) {
    console.error(err);
    return errorResponse(`Server error: ${err.message}`, 500);
  }
}
