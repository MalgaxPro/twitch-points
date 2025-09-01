// admin-routes.js
module.exports = function setupAdminRoutes(app, pool, getUserLogin) {
  function ensureIsAdmin(req, res, next) {
    const who = (getUserLogin && getUserLogin(req)) || '';
    if (who === 'malgax') return next();
    // Consenti GET a tutti per leggere (se vuoi chiudere, rimuovi la riga sotto)
    if (req.method === 'GET') return next();
    return res.status(403).json({ error: 'forbidden' });
  }

  // GET /admin/used-cards
  app.get('/admin/used-cards', ensureIsAdmin, async (req, res) => {
    try {
      const { kind, status = 'all', user, item, from, to, limit = 100 } = req.query;

      const where = [`pt.event_type = 'use'`];
      const params = [];

      if (kind) { params.push(kind); where.push(`i.kind = $${params.length}`); }
      if (user) { params.push(user); where.push(`LOWER(COALESCE(pt.user_login, u.username)) = LOWER($${params.length})`); }
      if (item) { params.push(`%${item}%`); where.push(`LOWER(i.name) LIKE LOWER($${params.length})`); }
      if (from) { params.push(new Date(from)); where.push(`pt.created_at >= $${params.length}`); }
      if (to)   { params.push(new Date(to));   where.push(`pt.created_at <= $${params.length}`); }
      if (status === 'pending') where.push(`COALESCE(pt.done,false) = false`);
      if (status === 'done')    where.push(`COALESCE(pt.done,false) = true`);

      params.push(Number(limit)); const limIdx = params.length;

      const sql = `
        SELECT
          pt.id,                                 -- Event ID
          pt.created_at,                         -- Quando
          COALESCE(pt.user_login, u.username) AS user_login, -- Utente
          pt.item_id,
          COALESCE(pt.done,false) AS done,
          i.name AS item_name,                   -- Carta
          i.kind AS kind                         -- Tipo (creature/incantesimo/istantanea)
        FROM point_transactions pt
        LEFT JOIN users u ON u.id = pt.user_id
        JOIN items i ON i.id = pt.item_id
        WHERE ${where.join(' AND ')}
        ORDER BY pt.created_at DESC
        LIMIT $${limIdx};
      `;

      const { rows } = await pool.query(sql, params);
      res.json({ items: rows });
    } catch (err) {
      console.error('ERR /admin/used-cards', err);
      res.status(500).json({ error: 'db_error' });
    }
  });

  // POST /admin/used-cards/complete  body: { id, done:true|false }
  app.post('/admin/used-cards/complete', ensureIsAdmin, async (req, res) => {
    try {
      const { id, done = true } = req.body || {};
      if (!id) return res.status(400).json({ error: 'missing_id' });
      await pool.query(`UPDATE point_transactions SET done = $1 WHERE id = $2`, [!!done, id]);
      res.json({ ok: true, id, done: !!done });
    } catch (err) {
      console.error('ERR /admin/used-cards/complete', err);
      res.status(500).json({ error: 'db_error' });
    }
  });
};
