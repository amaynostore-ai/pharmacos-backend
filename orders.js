const express = require('express');
const supabase = require('../config/supabase');
const { authMiddleware, adminOnly } = require('../middleware/auth');

const router = express.Router();
router.use(authMiddleware);

// ─── GET /orders ──────────────────────────────────────────────
router.get('/', async (req, res) => {
  try {
    let query = supabase.from('orders')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(500);

    if (req.user.role === 'agent') {
      query = query.eq('agent_name', req.user.name);
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
      agent_name: req.body.agent_name || req.user.name,
      ship_status: req.body.ship_status || 'pending',
      ship_company: req.body.ship_company || 'Glivo',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    // حذف الحقول غير الموجودة في Supabase
    delete order.agent;
    delete order.shipStatus;
    delete order.shipCompany;
    delete order.shipReason;

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
    const updates = {
      ...req.body,
      updated_at: new Date().toISOString(),
    };

    // حذف الحقول غير الموجودة في Supabase
    delete updates.agent;
    delete updates.shipStatus;
    delete updates.shipCompany;
    delete updates.shipReason;
    delete updates.id;
    delete updates.created_at;

    const { data, error } = await supabase
      .from('orders')
      .update(updates)
      .eq('id', id)
      .select()
      .single();

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
    const { error } = await supabase.from('orders').delete().eq('id', id);
    if (error) throw error;
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
