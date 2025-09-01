// admin-routes.js
module.exports = function setupAdminRoutes(app, pool, getUserLogin) {
  // getUserLogin(req) deve restituire il login in minuscolo (es. 'malgax')
  function ensureIsAdmin(req, res, next) {
    const who = (getUserLogin && getUserLogin(req)) || '';
    if (who === 'malgax') return next();
    // CONSENTI lettura anche se non admin? metti return next() qui sopra.
    if (req.method === 'GET') return next(); // <-- lettura pubblica (se vuoi, tieni così)
    return res.status(403).json({ error: 'forbidden' });
  }

  // GET /admin/used-cards
  app.get('/admin/used-cards', ensureIsAdmin, async (req, res) => {
    try {
      const { kind, status = 'all', user, item, from, to, limit = 100 } = req.query;

      const where = [`pt.event_type = 'use'`];
      const params = [];

      if (kind) { params.push(kind); where.push(`i.kind = $${params.length}`); }
      if (user) { params.push(user); where.push(`LOWER(pt.user_login) = LOWER($${params.length})`); }
      if (item) { params.push(`%${item}%`); where.push(`LOWER(i.name) LIKE LOWER($${params.length})`); }
      if (from) { params.push(new Date(from)); where.push(`pt.created_at >= $${params.length}`); }
      if (to)   { params.push(new Date(to));   where.push(`pt.created_at <= $${params.length}`); }
      if (status === 'pending') where.push(`COALESCE(pt.done,false) = false`);
      if (status === 'done')    where.push(`COALESCE(pt.done,false) = true`);

      params.push(Number(limit)); const limIdx = params.length;

      const sql = `
        SELECT pt.id, pt.created_at, pt.user_login, pt.item_id,
               COALESCE(pt.done,false) AS done,
               i.name AS item_name, i.kind AS kind
        FROM point_transactions pt
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
