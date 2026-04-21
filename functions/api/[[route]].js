/**
 * COE API — Center of Excellence Checklist (Cloudflare Pages Function)
 * v3: Cloudflare Access OTP + dynamic checklist templates + role-based access
 *
 * Auth (handled by Cloudflare Access):
 *   Cloudflare Access sends Cf-Access-Jwt-Assertion header with user email.
 *   API reads email → looks up user in D1 → gets role/permissions.
 *   Legacy OTP + employee_id/pin login kept as fallback.
 *
 *   GET  /api/auth/me             — Get current user profile (from CF Access or JWT)
 *
 * Stores:
 *   GET  /api/stores              — List stores (scoped by role)
 *
 * Checklist Templates:
 *   GET  /api/templates           — List templates for current role
 *   GET  /api/templates/:id       — Get template with categories + items
 *   POST /api/templates           — Create template (VP only)
 *   PUT  /api/templates/:id       — Update template (VP only)
 *   POST /api/templates/:id/items — Add/update items (VP only)
 *
 * Inspections:
 *   POST /api/inspections         — Submit inspection
 *   GET  /api/inspections         — List inspections (scoped)
 *   GET  /api/inspections/:id     — Get single inspection
 *   PUT  /api/inspections/:id/review — Review an inspection (DM/GM/VP)
 *
 * Dashboard:
 *   GET  /api/dashboard           — Dashboard data (scoped by role)
 *
 * Users (GM/VP):
 *   GET  /api/users               — List users
 *   POST /api/users               — Create user
 *   PUT  /api/users/:id           — Update user
 */

// ── Config ───────────────────────────────────────────────────
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

const ALLOWED_DOMAINS = ['supersports.co.th', 'crcsports.co.th'];
const OTP_EXPIRY_MINUTES = 5;
const OTP_MAX_ATTEMPTS = 3;
const OTP_RATE_LIMIT = 3; // max requests per 15 min
const JWT_SECRET = 'coe-supersports-secret-2026';
const ROLE_HIERARCHY = { VP: 4, GM: 3, DM: 2, SM: 1 };

// ── Helpers ──────────────────────────────────────────────────
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS },
  });
}

function errorResponse(message, status = 400) {
  return jsonResponse({ error: message }, status);
}

function hasRole(user, minRole) {
  return (ROLE_HIERARCHY[user.role] || 0) >= (ROLE_HIERARCHY[minRole] || 99);
}

// ── JWT ──────────────────────────────────────────────────────
async function createToken(payload) {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = btoa(JSON.stringify({ ...payload, exp: Date.now() + 24 * 60 * 60 * 1000 }));
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(`${header}.${body}`));
  return `${header}.${body}.${btoa(String.fromCharCode(...new Uint8Array(sig)))}`;
}

async function verifyToken(token) {
  try {
    const [header, body, sig] = token.split('.');
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey('raw', enc.encode(JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const sigBytes = Uint8Array.from(atob(sig), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, enc.encode(`${header}.${body}`));
    if (!valid) return null;
    const payload = JSON.parse(atob(body));
    if (payload.exp < Date.now()) return null;
    return payload;
  } catch { return null; }
}

async function authenticate(request) {
  // Method 1: Cloudflare Access JWT (preferred)
  const cfJwt = request.headers.get('Cf-Access-Jwt-Assertion');
  if (cfJwt) {
    try {
      // Decode the CF Access JWT payload (middle part) to get email
      const [, body] = cfJwt.split('.');
      const payload = JSON.parse(atob(body));
      if (payload.email) {
        return { email: payload.email, _source: 'cf-access' };
      }
    } catch { /* fall through to other methods */ }
  }

  // Method 2: Our own JWT (Bearer token)
  const auth = request.headers.get('Authorization');
  if (auth && auth.startsWith('Bearer ')) {
    const token = auth.slice(7);
    const payload = await verifyToken(token);
    if (payload) return { ...payload, _source: 'jwt' };
  }

  return null;
}

// Resolve auth identity to full user object from DB
async function resolveUser(authPayload, DB) {
  if (!authPayload) return null;

  // If from CF Access, look up by email
  if (authPayload._source === 'cf-access') {
    const user = await DB.prepare(
      'SELECT id, employee_id, email, name, role, store_name, district, division FROM users WHERE email = ? AND active = 1'
    ).bind(authPayload.email.toLowerCase()).first();
    return user;
  }

  // If from our JWT, we already have role info but refresh from DB for latest
  if (authPayload.id) {
    const user = await DB.prepare(
      'SELECT id, employee_id, email, name, role, store_name, district, division FROM users WHERE id = ? AND active = 1'
    ).bind(authPayload.id).first();
    return user || authPayload; // fallback to JWT payload if DB lookup fails
  }

  return authPayload;
}

// ── OTP Helpers ──────────────────────────────────────────────
function generateOTP() {
  const arr = new Uint32Array(1);
  crypto.getRandomValues(arr);
  return String(arr[0] % 1000000).padStart(6, '0');
}

function isAllowedEmail(email) {
  const domain = email.split('@')[1]?.toLowerCase();
  // Also allow the VP's personal email for testing
  if (email.toLowerCase() === 'pawit.wayachut@gmail.com') return true;
  return ALLOWED_DOMAINS.includes(domain);
}

async function sendOTPEmail(email, code, env) {
  // Use Resend API if configured, otherwise log for dev/testing
  const RESEND_KEY = env.RESEND_API_KEY;

  if (RESEND_KEY) {
    const resp = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${RESEND_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: 'COE Checklist <noreply@sspopr.com>',
        to: [email],
        subject: `รหัส OTP สำหรับเข้าใช้ COE Checklist: ${code}`,
        html: `
          <div style="font-family:sans-serif;max-width:400px;margin:0 auto;padding:20px;">
            <h2 style="color:#E8192C;margin-bottom:16px;">COE Checklist</h2>
            <p>รหัส OTP สำหรับเข้าสู่ระบบ:</p>
            <div style="font-size:32px;font-weight:bold;letter-spacing:8px;text-align:center;padding:20px;background:#f5f5f5;border-radius:8px;margin:16px 0;">
              ${code}
            </div>
            <p style="color:#666;font-size:14px;">รหัสนี้จะหมดอายุใน ${OTP_EXPIRY_MINUTES} นาที</p>
            <p style="color:#999;font-size:12px;">หากคุณไม่ได้ร้องขอ กรุณาเพิกเฉยอีเมลนี้</p>
          </div>
        `,
      }),
    });
    return resp.ok;
  }

  // Dev mode: log OTP to console (visible in Cloudflare dashboard logs)
  console.log(`[DEV OTP] ${email} → ${code}`);
  return true;
}

// ── Main Handler ─────────────────────────────────────────────
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
    return errorResponse('Database not configured', 500);
  }

  try {
    // ════════════════════════════════════════════════════════
    // AUTH ROUTES (public)
    // ════════════════════════════════════════════════════════

    // ── Request OTP ─────────────────────────────────────
    if (path === '/api/auth/request-otp' && method === 'POST') {
      const { email } = await request.json();
      if (!email) return errorResponse('email required');

      const emailLower = email.toLowerCase().trim();
      if (!isAllowedEmail(emailLower)) {
        return errorResponse('อีเมลนี้ไม่มีสิทธิ์เข้าใช้งาน กรุณาใช้อีเมล @supersports.co.th หรือ @crcsports.co.th', 403);
      }

      // Check user exists
      const user = await DB.prepare('SELECT id, email, name, role FROM users WHERE email = ? AND active = 1').bind(emailLower).first();
      if (!user) {
        return errorResponse('ไม่พบบัญชีผู้ใช้สำหรับอีเมลนี้ กรุณาติดต่อผู้ดูแลระบบ', 404);
      }

      // Rate limit: max 3 OTPs per email per 15 minutes
      const fifteenMinsAgo = new Date(Date.now() - 15 * 60 * 1000).toISOString();
      const { results: recentOTPs } = await DB.prepare(
        'SELECT COUNT(*) as cnt FROM otp_codes WHERE email = ? AND created_at > ?'
      ).bind(emailLower, fifteenMinsAgo).all();

      if (recentOTPs[0]?.cnt >= OTP_RATE_LIMIT) {
        return errorResponse('ส่ง OTP บ่อยเกินไป กรุณารอ 15 นาที', 429);
      }

      // Generate and store OTP
      const code = generateOTP();
      const expiresAt = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000).toISOString();

      await DB.prepare(
        'INSERT INTO otp_codes (email, code, expires_at) VALUES (?, ?, ?)'
      ).bind(emailLower, code, expiresAt).run();

      // Send email
      const sent = await sendOTPEmail(emailLower, code, env);

      return jsonResponse({
        message: 'OTP sent',
        email: emailLower,
        // Include OTP in dev mode (no Resend key configured)
        ...(env.RESEND_API_KEY ? {} : { dev_otp: code }),
      });
    }

    // ── Verify OTP ──────────────────────────────────────
    if (path === '/api/auth/verify-otp' && method === 'POST') {
      const { email, code } = await request.json();
      if (!email || !code) return errorResponse('email and code required');

      const emailLower = email.toLowerCase().trim();
      const now = new Date().toISOString();

      // Find valid OTP
      const otp = await DB.prepare(
        'SELECT id, attempts FROM otp_codes WHERE email = ? AND code = ? AND used = 0 AND expires_at > ? ORDER BY created_at DESC LIMIT 1'
      ).bind(emailLower, code, now).first();

      if (!otp) {
        // Check if there's an unused OTP to increment attempts
        const latestOtp = await DB.prepare(
          'SELECT id, attempts FROM otp_codes WHERE email = ? AND used = 0 AND expires_at > ? ORDER BY created_at DESC LIMIT 1'
        ).bind(emailLower, now).first();

        if (latestOtp) {
          const newAttempts = (latestOtp.attempts || 0) + 1;
          await DB.prepare('UPDATE otp_codes SET attempts = ? WHERE id = ?').bind(newAttempts, latestOtp.id).run();

          if (newAttempts >= OTP_MAX_ATTEMPTS) {
            await DB.prepare('UPDATE otp_codes SET used = 1 WHERE id = ?').bind(latestOtp.id).run();
            return errorResponse('OTP ไม่ถูกต้อง ครบ 3 ครั้ง กรุณาขอ OTP ใหม่', 401);
          }
        }
        return errorResponse('OTP ไม่ถูกต้องหรือหมดอายุ', 401);
      }

      // Mark OTP as used
      await DB.prepare('UPDATE otp_codes SET used = 1 WHERE id = ?').bind(otp.id).run();

      // Get user
      const user = await DB.prepare(
        'SELECT id, employee_id, email, name, role, store_name, district, division FROM users WHERE email = ? AND active = 1'
      ).bind(emailLower).first();

      if (!user) return errorResponse('User not found', 404);

      // Create JWT
      const token = await createToken({
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        store_name: user.store_name,
        district: user.district,
        division: user.division,
      });

      return jsonResponse({ token, user });
    }

    // ── Legacy Login (employee_id + pin) ────────────────
    if (path === '/api/auth/login' && method === 'POST') {
      const { employee_id, pin } = await request.json();
      if (!employee_id || !pin) return errorResponse('employee_id and pin required');

      const user = await DB.prepare(
        'SELECT id, employee_id, email, name, role, store_name, district, division FROM users WHERE employee_id = ? AND pin = ? AND active = 1'
      ).bind(employee_id, pin).first();

      if (!user) return errorResponse('Invalid credentials', 401);

      const token = await createToken({
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        store_name: user.store_name,
        district: user.district,
        division: user.division,
      });

      return jsonResponse({ token, user });
    }

    // ── Stores (public) ─────────────────────────────────
    if (path === '/api/stores' && method === 'GET') {
      const { results } = await DB.prepare(
        'SELECT id, name, brand, region, district FROM stores WHERE active = 1 ORDER BY brand, name'
      ).all();
      return jsonResponse({ stores: results });
    }

    // ════════════════════════════════════════════════════════
    // PROTECTED ROUTES (require auth via CF Access or JWT)
    // ════════════════════════════════════════════════════════
    const authPayload = await authenticate(request);
    if (!authPayload) return errorResponse('Unauthorized', 401);
    const user = await resolveUser(authPayload, DB);
    if (!user) return errorResponse('ไม่พบบัญชีผู้ใช้ กรุณาติดต่อผู้ดูแลระบบ', 403);

    // ── Auth: Me ────────────────────────────────────────
    if (path === '/api/auth/me' && method === 'GET') {
      const dbUser = await DB.prepare(
        'SELECT id, employee_id, email, name, role, store_name, district, division FROM users WHERE id = ? AND active = 1'
      ).bind(user.id).first();
      if (!dbUser) return errorResponse('User not found', 404);
      return jsonResponse({ user: dbUser });
    }

    // ════════════════════════════════════════════════════════
    // CHECKLIST TEMPLATES
    // ════════════════════════════════════════════════════════

    // ── List Templates (for current role) ───────────────
    if (path === '/api/templates' && method === 'GET') {
      const today = new Date().toISOString().split('T')[0];
      const showAll = url.searchParams.get('all') === '1' && hasRole(user, 'VP');

      let query = `SELECT id, code, name_th, name_en, description, assigned_role, reviewed_by_role, frequency, active_from, active_to
                    FROM checklist_templates WHERE active = 1`;
      const params = [];

      if (!showAll) {
        // Show templates the user can DO + templates the user can REVIEW
        query += ` AND (assigned_role = ? OR reviewed_by_role = ?`;
        params.push(user.role, user.role);
        // VP sees everything
        if (hasRole(user, 'VP')) {
          query += ` OR 1=1`;
        }
        query += `)`;
      }

      query += ` ORDER BY assigned_role, name_th`;
      const { results } = await DB.prepare(query).bind(...params).all();

      // Filter by date range
      const filtered = results.filter(t => {
        if (t.active_from && t.active_from > today) return false;
        if (t.active_to && t.active_to < today) return false;
        return true;
      });

      return jsonResponse({ templates: filtered });
    }

    // ── Get Template Detail ─────────────────────────────
    const templateMatch = path.match(/^\/api\/templates\/(\d+)$/);
    if (templateMatch && method === 'GET') {
      const templateId = templateMatch[1];
      const today = new Date().toISOString().split('T')[0];

      const template = await DB.prepare('SELECT * FROM checklist_templates WHERE id = ?').bind(templateId).first();
      if (!template) return errorResponse('Template not found', 404);

      const { results: categories } = await DB.prepare(
        'SELECT * FROM checklist_categories WHERE template_id = ? AND active = 1 ORDER BY sort_order'
      ).bind(templateId).all();

      const catIds = categories.map(c => c.id);
      let items = [];
      if (catIds.length > 0) {
        // D1 doesn't support IN with bind, so query per category
        for (const cat of categories) {
          const { results: catItems } = await DB.prepare(
            `SELECT * FROM checklist_items WHERE category_id = ? AND active = 1
             AND (active_from IS NULL OR active_from <= ?)
             AND (active_to IS NULL OR active_to >= ?)
             ORDER BY sort_order`
          ).bind(cat.id, today, today).all();
          cat.items = catItems;
        }
      }

      return jsonResponse({ template, categories });
    }

    // ── Create Template (VP only) ───────────────────────
    if (path === '/api/templates' && method === 'POST') {
      if (!hasRole(user, 'VP')) return errorResponse('Forbidden', 403);
      const { code, name_th, name_en, description, assigned_role, reviewed_by_role, frequency, active_from, active_to } = await request.json();
      if (!code || !name_th || !name_en) return errorResponse('code, name_th, name_en required');

      const result = await DB.prepare(
        `INSERT INTO checklist_templates (code, name_th, name_en, description, assigned_role, reviewed_by_role, frequency, active_from, active_to)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(code, name_th, name_en, description || '', assigned_role || 'SM', reviewed_by_role || 'DM', frequency || 'daily', active_from || null, active_to || null).run();

      return jsonResponse({ id: result.meta.last_row_id, message: 'Template created' }, 201);
    }

    // ── Update Template (VP only) ───────────────────────
    const templateUpdateMatch = path.match(/^\/api\/templates\/(\d+)$/);
    if (templateUpdateMatch && method === 'PUT') {
      if (!hasRole(user, 'VP')) return errorResponse('Forbidden', 403);
      const templateId = templateUpdateMatch[1];
      const data = await request.json();

      const fields = [];
      const values = [];
      for (const key of ['name_th', 'name_en', 'description', 'assigned_role', 'reviewed_by_role', 'frequency', 'active', 'active_from', 'active_to']) {
        if (data[key] !== undefined) {
          fields.push(`${key} = ?`);
          values.push(data[key]);
        }
      }
      if (fields.length === 0) return errorResponse('No fields to update');

      fields.push("updated_at = datetime('now')");
      values.push(templateId);

      await DB.prepare(`UPDATE checklist_templates SET ${fields.join(', ')} WHERE id = ?`).bind(...values).run();
      return jsonResponse({ message: 'Template updated' });
    }

    // ── Add/Update Items for a Template (VP only) ───────
    const itemsMatch = path.match(/^\/api\/templates\/(\d+)\/items$/);
    if (itemsMatch && method === 'POST') {
      if (!hasRole(user, 'VP')) return errorResponse('Forbidden', 403);
      const templateId = itemsMatch[1];
      const { categories } = await request.json();

      if (!categories || !Array.isArray(categories)) return errorResponse('categories array required');

      for (const cat of categories) {
        let categoryId = cat.id;

        // Create or update category
        if (!categoryId) {
          const result = await DB.prepare(
            'INSERT INTO checklist_categories (template_id, sort_order, icon, name_th, name_en) VALUES (?, ?, ?, ?, ?)'
          ).bind(templateId, cat.sort_order || 0, cat.icon || '', cat.name_th, cat.name_en).run();
          categoryId = result.meta.last_row_id;
        } else {
          await DB.prepare(
            'UPDATE checklist_categories SET sort_order = ?, icon = ?, name_th = ?, name_en = ?, active = ? WHERE id = ?'
          ).bind(cat.sort_order || 0, cat.icon || '', cat.name_th, cat.name_en, cat.active !== undefined ? cat.active : 1, categoryId).run();
        }

        // Upsert items
        if (cat.items && Array.isArray(cat.items)) {
          for (const item of cat.items) {
            if (item.id) {
              await DB.prepare(
                `UPDATE checklist_items SET sort_order=?, text_th=?, text_en=?, item_type=?, require_photo=?, require_note=?,
                 score_max=?, score_labels=?, active=?, active_from=?, active_to=?, condition_tag=?, ai_check_enabled=?, ai_check_prompt=?
                 WHERE id=?`
              ).bind(
                item.sort_order || 0, item.text_th, item.text_en || '', item.item_type || 'checkbox',
                item.require_photo ? 1 : 0, item.require_note ? 1 : 0,
                item.score_max || null, item.score_labels || null,
                item.active !== undefined ? item.active : 1,
                item.active_from || null, item.active_to || null,
                item.condition_tag || null, item.ai_check_enabled ? 1 : 0, item.ai_check_prompt || null,
                item.id
              ).run();
            } else {
              await DB.prepare(
                `INSERT INTO checklist_items (category_id, sort_order, text_th, text_en, item_type, require_photo, require_note,
                 score_max, score_labels, active, active_from, active_to, condition_tag, ai_check_enabled, ai_check_prompt)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
              ).bind(
                categoryId, item.sort_order || 0, item.text_th, item.text_en || '', item.item_type || 'checkbox',
                item.require_photo ? 1 : 0, item.require_note ? 1 : 0,
                item.score_max || null, item.score_labels || null, 1,
                item.active_from || null, item.active_to || null,
                item.condition_tag || null, item.ai_check_enabled ? 1 : 0, item.ai_check_prompt || null
              ).run();
            }
          }
        }
      }

      return jsonResponse({ message: 'Items updated' });
    }

    // ════════════════════════════════════════════════════════
    // INSPECTIONS
    // ════════════════════════════════════════════════════════

    // ── Submit Inspection ───────────────────────────────
    if (path === '/api/inspections' && method === 'POST') {
      const data = await request.json();
      const { store_name, template_id, date, overall_score, total_items, passed_items, categories_scores, ai_summary, items } = data;

      if (!store_name || !date) return errorResponse('store_name and date required');

      const result = await DB.prepare(
        `INSERT INTO inspections (store_name, inspector_name, inspector_id, template_id, date, overall_score, total_items, passed_items, status, review_status, categories_scores, ai_summary)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'completed', 'pending', ?, ?)`
      ).bind(
        store_name, user.name, user.email || user.employee_id, template_id || null, date,
        overall_score || 0, total_items || 0, passed_items || 0,
        JSON.stringify(categories_scores || {}), ai_summary || ''
      ).run();

      const inspectionId = result.meta.last_row_id;

      if (items && items.length > 0) {
        const stmt = DB.prepare(
          `INSERT INTO inspection_items (inspection_id, category_id, category_name, item_index, item_text, status, item_type, score_value, note, photo_data)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        );
        const batch = items.map(item =>
          stmt.bind(
            inspectionId, item.category_id, item.category_name, item.item_index, item.item_text,
            item.status || 'unchecked', item.item_type || 'checkbox',
            item.score_value || null, item.note || null, item.photo_data || null
          )
        );
        await DB.batch(batch);
      }

      return jsonResponse({ id: inspectionId, message: 'Inspection saved' }, 201);
    }

    // ── List Inspections (scoped by role) ────────────────
    if (path === '/api/inspections' && method === 'GET') {
      const store = url.searchParams.get('store');
      const date = url.searchParams.get('date');
      const templateId = url.searchParams.get('template_id');
      const reviewStatus = url.searchParams.get('review_status');
      const limit = parseInt(url.searchParams.get('limit') || '50');

      let query = `SELECT i.id, i.store_name, i.inspector_name, i.template_id, i.date, i.overall_score,
                          i.total_items, i.passed_items, i.status, i.review_status, i.reviewed_by, i.created_at,
                          t.name_th as template_name
                   FROM inspections i
                   LEFT JOIN checklist_templates t ON t.id = i.template_id
                   WHERE 1=1`;
      const params = [];

      // Scope by role
      if (user.role === 'SM' && user.store_name) {
        query += ' AND i.store_name = ?';
        params.push(user.store_name);
      } else if (user.role === 'DM' && user.district) {
        query += ' AND i.store_name IN (SELECT name FROM stores WHERE district = ?)';
        params.push(user.district);
      } else if (user.role === 'GM' && user.division) {
        query += ' AND i.store_name IN (SELECT name FROM stores WHERE region = ?)';
        params.push(user.division);
      }
      // VP sees all

      if (store) { query += ' AND i.store_name = ?'; params.push(store); }
      if (date) { query += ' AND i.date = ?'; params.push(date); }
      if (templateId) { query += ' AND i.template_id = ?'; params.push(templateId); }
      if (reviewStatus) { query += ' AND i.review_status = ?'; params.push(reviewStatus); }

      query += ' ORDER BY i.created_at DESC LIMIT ?';
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
        'SELECT * FROM inspection_items WHERE inspection_id = ? ORDER BY category_id, item_index'
      ).bind(id).all();

      return jsonResponse({ inspection, items });
    }

    // ── Review Inspection (DM/GM/VP) ────────────────────
    const reviewMatch = path.match(/^\/api\/inspections\/(\d+)\/review$/);
    if (reviewMatch && method === 'PUT') {
      if (!hasRole(user, 'DM')) return errorResponse('Forbidden', 403);

      const id = reviewMatch[1];
      const { status, note } = await request.json();
      if (!status || !['approved', 'needs_improvement', 'rejected'].includes(status)) {
        return errorResponse('status must be: approved, needs_improvement, or rejected');
      }

      await DB.prepare(
        'UPDATE inspections SET review_status = ?, reviewed_by = ?, review_note = ? WHERE id = ?'
      ).bind(status, user.name, note || null, id).run();

      return jsonResponse({ message: 'Review saved' });
    }

    // ════════════════════════════════════════════════════════
    // DASHBOARD (scoped by role)
    // ════════════════════════════════════════════════════════
    if (path === '/api/dashboard' && method === 'GET') {
      const date = url.searchParams.get('date') || new Date().toISOString().split('T')[0];
      const month = date.substring(0, 7);

      // Scope filter
      let storeFilter = '';
      const storeParams = [];
      if (user.role === 'SM' && user.store_name) {
        storeFilter = 'AND i.store_name = ?';
        storeParams.push(user.store_name);
      } else if (user.role === 'DM' && user.district) {
        storeFilter = 'AND i.store_name IN (SELECT name FROM stores WHERE district = ?)';
        storeParams.push(user.district);
      } else if (user.role === 'GM' && user.division) {
        storeFilter = 'AND i.store_name IN (SELECT name FROM stores WHERE region = ?)';
        storeParams.push(user.division);
      }

      // Today's inspections
      const { results: todayInspections } = await DB.prepare(
        `SELECT i.store_name, i.inspector_name, i.overall_score, i.total_items, i.passed_items,
                i.review_status, i.created_at, t.name_th as template_name
         FROM inspections i LEFT JOIN checklist_templates t ON t.id = i.template_id
         WHERE i.date = ? ${storeFilter} ORDER BY i.created_at DESC`
      ).bind(date, ...storeParams).all();

      // Monthly summary
      const { results: monthSummary } = await DB.prepare(
        `SELECT i.store_name, COUNT(*) as inspection_count,
                ROUND(AVG(i.overall_score), 1) as avg_score,
                MIN(i.overall_score) as min_score, MAX(i.overall_score) as max_score,
                SUM(CASE WHEN i.review_status = 'approved' THEN 1 ELSE 0 END) as approved_count,
                SUM(CASE WHEN i.review_status = 'pending' THEN 1 ELSE 0 END) as pending_review
         FROM inspections i WHERE i.date LIKE ? || '%' ${storeFilter}
         GROUP BY i.store_name ORDER BY avg_score DESC`
      ).bind(month, ...storeParams).all();

      // Missing stores today
      let storesQuery = 'SELECT name FROM stores WHERE active = 1';
      const storesParams = [];
      if (user.role === 'DM' && user.district) {
        storesQuery += ' AND district = ?';
        storesParams.push(user.district);
      } else if (user.role === 'GM' && user.division) {
        storesQuery += ' AND region = ?';
        storesParams.push(user.division);
      } else if (user.role === 'SM' && user.store_name) {
        storesQuery += ' AND name = ?';
        storesParams.push(user.store_name);
      }

      const { results: allStores } = await DB.prepare(storesQuery).bind(...storesParams).all();
      const inspectedToday = new Set(todayInspections.map(i => i.store_name));
      const missingStores = allStores.map(s => s.name).filter(name => !inspectedToday.has(name));

      // Overall stats
      const { results: overallStats } = await DB.prepare(
        `SELECT COUNT(*) as total_inspections, ROUND(AVG(i.overall_score), 1) as avg_score,
                COUNT(DISTINCT i.store_name) as stores_inspected
         FROM inspections i WHERE i.date LIKE ? || '%' ${storeFilter}`
      ).bind(month, ...storeParams).all();

      // Pending reviews count (for DM/GM/VP)
      let pendingReviews = 0;
      if (hasRole(user, 'DM')) {
        const { results: pr } = await DB.prepare(
          `SELECT COUNT(*) as cnt FROM inspections i WHERE i.review_status = 'pending' ${storeFilter}`
        ).bind(...storeParams).all();
        pendingReviews = pr[0]?.cnt || 0;
      }

      return jsonResponse({
        date, month,
        today: { inspections: todayInspections, count: todayInspections.length, missing_stores: missingStores },
        month_summary: monthSummary,
        overall: overallStats[0] || {},
        pending_reviews: pendingReviews,
      });
    }

    // ════════════════════════════════════════════════════════
    // USERS (GM/VP only)
    // ════════════════════════════════════════════════════════
    if (path === '/api/users' && method === 'GET') {
      if (!hasRole(user, 'GM')) return errorResponse('Forbidden', 403);
      const { results } = await DB.prepare(
        'SELECT id, employee_id, email, name, role, store_name, district, division, active, created_at FROM users ORDER BY role, name'
      ).all();
      return jsonResponse({ users: results });
    }

    if (path === '/api/users' && method === 'POST') {
      if (!hasRole(user, 'GM')) return errorResponse('Forbidden', 403);
      const { email, name, role, employee_id, store_name, district, division, pin } = await request.json();
      if (!email || !name) return errorResponse('email and name required');

      const emailLower = email.toLowerCase().trim();
      if (!isAllowedEmail(emailLower)) {
        return errorResponse('อีเมลต้องเป็น @supersports.co.th หรือ @crcsports.co.th');
      }

      try {
        await DB.prepare(
          `INSERT INTO users (email, name, role, employee_id, store_name, district, division, pin)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
        ).bind(emailLower, name, role || 'SM', employee_id || null, store_name || null, district || null, division || null, pin || '0000').run();
        return jsonResponse({ message: 'User created' }, 201);
      } catch (err) {
        if (err.message.includes('UNIQUE')) return errorResponse('Email or Employee ID already exists', 409);
        throw err;
      }
    }

    const userUpdateMatch = path.match(/^\/api\/users\/(\d+)$/);
    if (userUpdateMatch && method === 'PUT') {
      if (!hasRole(user, 'GM')) return errorResponse('Forbidden', 403);
      const userId = userUpdateMatch[1];
      const data = await request.json();

      const fields = [];
      const values = [];
      for (const key of ['name', 'role', 'email', 'employee_id', 'store_name', 'district', 'division', 'phone', 'active']) {
        if (data[key] !== undefined) {
          fields.push(`${key} = ?`);
          values.push(data[key]);
        }
      }
      if (fields.length === 0) return errorResponse('No fields to update');
      values.push(userId);

      await DB.prepare(`UPDATE users SET ${fields.join(', ')} WHERE id = ?`).bind(...values).run();
      return jsonResponse({ message: 'User updated' });
    }

    // ════════════════════════════════════════════════════════
    // DSR (Daily Sales Report) ROUTES
    // ════════════════════════════════════════════════════════

    // ── POST /api/dsr/upload ─────────────────────────────
    if (path === '/api/dsr/upload' && method === 'POST') {
      if (!hasRole(user, 'DM')) return errorResponse('Forbidden: DM or higher required', 403);

      const body = await request.json();
      const { month, data_day, kpi, daily, stores, mono } = body;

      if (!month || !data_day || !kpi || !daily || !stores || !mono) {
        return errorResponse('Missing required fields: month, data_day, kpi, daily, stores, mono');
      }

      try {
        // Clear existing data for this month (REPLACE mode)
        await DB.prepare('DELETE FROM dsr_kpi WHERE month = ?').bind(month).run();
        await DB.prepare('DELETE FROM dsr_summary WHERE month = ?').bind(month).run();
        await DB.prepare('DELETE FROM dsr_stores WHERE month = ?').bind(month).run();
        await DB.prepare('DELETE FROM dsr_mono WHERE month = ?').bind(month).run();

        // Insert KPI
        await DB.prepare(`
          INSERT INTO dsr_kpi (month, data_day, ssp_daily, ssp_daily_ly, ssp_mtd, ssp_mtd_ly, ssp_monthly_target,
            runrate, ly_full_month, bkk_mtd, bkk_mtd_ly, bkk_target, upc_mtd, upc_mtd_ly, upc_target,
            mono_mtd, mono_mtd_ly, today_target, mtd_target, forecast_landing)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          month, data_day,
          kpi.ssp_daily || 0, kpi.ssp_daily_ly || 0, kpi.ssp_mtd || 0, kpi.ssp_mtd_ly || 0, kpi.ssp_monthly_target || 0,
          kpi.runrate || 0, kpi.ly_full_month || 0, kpi.bkk_mtd || 0, kpi.bkk_mtd_ly || 0, kpi.bkk_target || 0,
          kpi.upc_mtd || 0, kpi.upc_mtd_ly || 0, kpi.upc_target || 0,
          kpi.mono_mtd || 0, kpi.mono_mtd_ly || 0, kpi.today_target || 0, kpi.mtd_target || 0, kpi.forecast_landing || 0
        ).run();

        // Insert daily summary (batch)
        if (Array.isArray(daily) && daily.length > 0) {
          const summaryStmt = DB.prepare(`
            INSERT INTO dsr_summary (month, data_day, day_num, day_date, day_type, ly_date, ly_sales, target, actual, bkk_actual, upc_actual)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `);
          const summaryBatch = daily.map(d => summaryStmt.bind(
            month, data_day, d.day_num, d.day_date, d.day_type, d.ly_date, d.ly_sales || 0, d.target || 0, d.actual || 0, d.bkk_actual || 0, d.upc_actual || 0
          ));
          await DB.batch(summaryBatch);
        }

        // Insert stores (batch)
        if (Array.isArray(stores) && stores.length > 0) {
          const storesStmt = DB.prepare(`
            INSERT INTO dsr_stores (month, data_day, region, dm, store_code, store_name, daily_ty, daily_ly, daily_pct, mtd_ty, mtd_ly, mtd_pct, target, pct_ach, avg_wd, avg_fri, avg_wknd, is_dm_total)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `);
          const storesBatch = stores.map(s => storesStmt.bind(
            month, data_day, s.region, s.dm, s.store_code, s.store_name, s.daily_ty || 0, s.daily_ly || 0, s.daily_pct || 0,
            s.mtd_ty || 0, s.mtd_ly || 0, s.mtd_pct || 0, s.target || 0, s.pct_ach || 0, s.avg_wd || 0, s.avg_fri || 0, s.avg_wknd || 0, s.is_dm_total ? 1 : 0
          ));
          await DB.batch(storesBatch);
        }

        // Insert mono (batch)
        if (Array.isArray(mono) && mono.length > 0) {
          const monoStmt = DB.prepare(`
            INSERT INTO dsr_mono (month, data_day, brand, store_name, daily_ty, daily_ly, daily_pct, mtd_ty, mtd_ly, mtd_pct)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `);
          const monoBatch = mono.map(m => monoStmt.bind(
            month, data_day, m.brand, m.store_name, m.daily_ty || 0, m.daily_ly || 0, m.daily_pct || 0,
            m.mtd_ty || 0, m.mtd_ly || 0, m.mtd_pct || 0
          ));
          await DB.batch(monoBatch);
        }

        // Log upload
        await DB.prepare(`
          INSERT INTO dsr_uploads (month, uploaded_by, uploaded_by_name, file_type, original_filename, data_day)
          VALUES (?, ?, ?, ?, ?, ?)
        `).bind(month, user.id || user.email, user.name, 'web_upload', 'dashboard_upload', data_day).run();

        return jsonResponse({
          message: 'DSR data uploaded successfully',
          month, data_day,
          daily_rows: daily.length,
          store_rows: stores.length,
          mono_rows: mono.length,
        }, 201);
      } catch (err) {
        console.error('DSR upload error:', err);
        return errorResponse(`Upload failed: ${err.message}`, 500);
      }
    }

    // ── GET /api/dsr/data ────────────────────────────────
    if (path === '/api/dsr/data' && method === 'GET') {
      const month = url.searchParams.get('month') || new Date().toISOString().substring(0, 7);
      try {
        const kpi = await DB.prepare('SELECT * FROM dsr_kpi WHERE month = ?').bind(month).first();
        const { results: daily } = await DB.prepare('SELECT * FROM dsr_summary WHERE month = ? ORDER BY day_num').bind(month).all();
        const { results: storesData } = await DB.prepare('SELECT * FROM dsr_stores WHERE month = ? ORDER BY region, dm, is_dm_total, store_code').bind(month).all();
        const { results: monoData } = await DB.prepare('SELECT * FROM dsr_mono WHERE month = ? ORDER BY brand, store_name').bind(month).all();
        const uploadInfo = await DB.prepare('SELECT * FROM dsr_uploads WHERE month = ? ORDER BY created_at DESC LIMIT 1').bind(month).first();

        return jsonResponse({ month, kpi: kpi || null, daily, stores: storesData, mono: monoData, upload_info: uploadInfo });
      } catch (err) {
        return errorResponse(`Failed to fetch DSR data: ${err.message}`, 500);
      }
    }

    // ── GET /api/dsr/months ──────────────────────────────
    if (path === '/api/dsr/months' && method === 'GET') {
      const { results } = await DB.prepare('SELECT DISTINCT month FROM dsr_kpi ORDER BY month DESC').all();
      return jsonResponse({ months: results.map(r => r.month) });
    }

    // ── DELETE /api/dsr/data ─────────────────────────────
    if (path === '/api/dsr/data' && method === 'DELETE') {
      if (!hasRole(user, 'DM')) return errorResponse('Forbidden: DM or higher required', 403);
      const month = url.searchParams.get('month');
      if (!month) return errorResponse('month parameter required');

      await DB.prepare('DELETE FROM dsr_kpi WHERE month = ?').bind(month).run();
      await DB.prepare('DELETE FROM dsr_summary WHERE month = ?').bind(month).run();
      await DB.prepare('DELETE FROM dsr_stores WHERE month = ?').bind(month).run();
      await DB.prepare('DELETE FROM dsr_mono WHERE month = ?').bind(month).run();
      await DB.prepare('DELETE FROM dsr_uploads WHERE month = ?').bind(month).run();

      return jsonResponse({ message: 'DSR data deleted', month });
    }

    return errorResponse('Not found', 404);

  } catch (err) {
    console.error(err);
    return errorResponse(`Server error: ${err.message}`, 500);
  }
}
