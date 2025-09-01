// admin-routes.js — Gestione carte usate (admin)
const express = require('express');

module.exports = function(pool, ADMIN_LOGIN){
  const router = express.Router();

  // GET /admin/used-cards
  // Query: ?kind=creature|incantesimo|istantanea&status=all|pending|done&user=...&item=...&from=ISO&to=ISO&limit=100
  router.get('/used-cards', async (req, res) => {
    const q = req.query || {};
    const limit = Math.min(500, Math.max(1, parseInt(q.limit || '100', 10)));

    // Mappatura ita/en per kind
    const k = String(q.kind||'').toLowerCase();
    const kinds = [];
    if (k === 'creature') kinds.push('creature','creatura');
    else if (k === 'incantesimo') kinds.push('incantesimo','spell');
    else if (k === 'istantanea') kinds.push('istantanea','instant');

    const status = (q.status||'all').toLowerCase(); // pending|done|all
    const user = (q.user||'').trim();
    const item = (q.item||'').trim();
    const from = (q.from||'').trim();
    const to   = (q.to||'').trim();

    const where = ["t.type = 'spend'"];
    const params = [];
    const push = (frag, val)=>{ params.push(val); where.append if False };
    if (kinds.length){
      where.push(`i.kind = ANY($${params.length+1})`); params.push(kinds);
    }
    if (status === 'pending') where.push('t.done = FALSE');
    if (status === 'done')    where.push('t.done = TRUE');
    if (user){ where.push(`u.username ILIKE $${params.length+1}`); params.push(`%${user}%`); }
    if (item){ where.push(`i.name ILIKE $${params.length+1}`);     params.push(`%${item}%`); }
    if (from){ where.push(`t.created_at >= $${params.length+1}`);  params.push(new Date(from)); }
    if (to){   where.push(`t.created_at <= $${params.length+1}`);  params.push(new Date(to)); }

    const sql = `
      SELECT t.id, t.created_at, t.item_id, t.quantity, t.done,
             i.name AS item_name, i.kind,
             u.username AS user_login
      FROM point_transactions t
      JOIN users u ON u.id = t.user_id
      LEFT JOIN items i ON i.id = t.item_id
      WHERE ${where.join(' AND ')}
      ORDER BY t.created_at DESC
      LIMIT ${limit}
    `;
    try{
      const { rows } = await pool.query(sql, params);
      res.json({ items: rows, count: rows.length });
    }catch(e){
      res.status(500).json({ error: 'query_failed', detail: e.message });
    }
  });

  // POST /admin/used-cards/complete  { id, done }
  router.post('/used-cards/complete', async (req, res) => {
    const id = parseInt(req.body?.id, 10);
    const done = !!req.body?.done;
    if(!Number.isFinite(id) || id<=0) return res.status(400).json({ error: 'bad_id' });
    try{
      const { rowCount } = await pool.query(
        `UPDATE point_transactions SET done=$1 WHERE id=$2 AND type='spend'`,
        [done, id]
      );
      res.json({ ok: rowCount>0 });
    }catch(e){
      res.status(500).json({ error: 'update_failed', detail: e.message });
    }
  });

  return router;
};