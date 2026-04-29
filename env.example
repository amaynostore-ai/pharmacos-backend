const express = require('express');
const supabase = require('../config/supabase');
const { authMiddleware, adminOnly } = require('../middleware/auth');

const router = express.Router();
router.use(authMiddleware);

// ─── Helper: filtre selon le rôle ───────────────────────────
function agentFilter(query, user) {
  // Un agent ne voit QUE ses propres commandes
  if (user.role === 'agent') {
    return query.eq('agent_name', user.name);
  }
  return query; // Admin voit tout
}

// ─── GET /orders ─────────────────────────────────────────────
router.get('/', async (req, res) => {
  try {
    let query = supabase.from('orders').select('*').order('created_at', { ascending: false });
    query = agentFilter(query, req.user);

    // Filtres optionnels
    if (req.query.status) query = query.eq('status', req.query.status);
    if (req.query.city)   query = query.eq('city', req.query.city);
    if (req.query.agent && req.user.role === 'admin') query = query.eq('agent_name', req.query.agent);

    // Recherche texte
    if (req.query.q) {
      const q = req.query.q;
      query = query.or(`name.ilike.%${q}%,phone.ilike.%${q}%,track.ilike.%${q}%`);
    }

    const { data, error } = await query;
    if (error) throw error;
    res.json({ orders: data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── POST /orders ─────────────────────────────────────────────
router.post('/', async (req, res) => {
  try {
    const order = {
      ...req.body,
      agent_name: req.user.role === 'admin' ? (req.body.agent_name || 'Admin') : req.user.name,
      created_at: new Date().toISOString(),
      ship_status: 'pending',
      call_count: 0,
    };

    // Validation minimale
    if (!order.name || !order.phone) {
      return res.status(400).json({ error: 'Nom et téléphone obligatoires' });
    }

    const { data, error } = await supabase.from('orders').insert(order).select().single();
    if (error) throw error;
    res.status(201).json({ order: data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── PUT /orders/:id ──────────────────────────────────────────
router.put('/:id', async (req, res) => {
  try {
    const { id } = req.params;

    // Vérification de propriété pour les agents
    if (req.user.role === 'agent') {
      const { data: existing } = await supabase
        .from('orders').select('agent_name').eq('id', id).single();
      if (!existing || existing.agent_name !== req.user.name) {
        return res.status(403).json({ error: 'Accès refusé' });
      }
    }

    // L'agent ne peut pas changer l'agent_name
    const updates = { ...req.body };
    if (req.user.role === 'agent') {
      delete updates.agent_name;
    }
    updates.updated_at = new Date().toISOString();

    const { data, error } = await supabase
      .from('orders').update(updates).eq('id', id).select().single();
    if (error) throw error;
    res.json({ order: data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── DELETE /orders/:id ───────────────────────────────────────
router.delete('/:id', async (req, res) => {
  try {
    const { id } = req.params;

    if (req.user.role === 'agent') {
      const { data: existing } = await supabase
        .from('orders').select('agent_name').eq('id', id).single();
      if (!existing || existing.agent_name !== req.user.name) {
        return res.status(403).json({ error: 'Accès refusé' });
      }
    }

    const { error } = await supabase.from('orders').delete().eq('id', id);
    if (error) throw error;
    res.json({ message: 'Supprimé' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── GET /orders/stats ────────────────────────────────────────
router.get('/stats/summary', async (req, res) => {
  try {
    let query = supabase.from('orders').select('status, price, ship_status, agent_name, created_at');
    query = agentFilter(query, req.user);
    const { data, error } = await query;
    if (error) throw error;

    const total = data.length;
    const confirmed = data.filter(o => o.status === 'مؤكد').length;
    const cancelled = data.filter(o => o.status === 'ملغى').length;
    const revenue = data.filter(o => o.status === 'مؤكد').reduce((s, o) => s + (o.price || 0), 0);
    const delivered = data.filter(o => o.ship_status === 'delivered').length;
    const inTransit = data.filter(o => ['pending','ready'].includes(o.ship_status)).length;

    res.json({ total, confirmed, cancelled, revenue, delivered, inTransit,
      rate: total ? Math.round(confirmed / total * 100) : 0 });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
