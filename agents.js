const express = require('express');
const supabase = require('../config/supabase');
const { authMiddleware, adminOnly } = require('../middleware/auth');

const router = express.Router();
router.use(authMiddleware);

// ─── GET /calllogs ────────────────────────────────────────────
router.get('/', async (req, res) => {
  try {
    let query = supabase.from('call_logs')
      .select('*').order('created_at', { ascending: false }).limit(100);

    if (req.user.role === 'agent') {
      query = query.eq('agent_name', req.user.name);
    }

    const { data, error } = await query;
    if (error) throw error;
    res.json({ logs: data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── POST /calllogs ───────────────────────────────────────────
router.post('/', async (req, res) => {
  try {
    const log = {
      ...req.body,
      agent_name: req.user.name,
      created_at: new Date().toISOString(),
    };

    const { data, error } = await supabase.from('call_logs').insert(log).select().single();
    if (error) throw error;

    // Mettre à jour la commande liée
    if (log.order_id) {
      const updates = {
        call_count: log.call_num,
        call_result: log.result,
        updated_at: new Date().toISOString(),
      };
      if (log.result === 'delivered')   updates.ship_status = 'delivered';
      if (log.result === 'cancelled')   updates.ship_status = 'cancelled';
      if (log.result === 'refused')     updates.ship_status = 'refused';
      if (log.result === 'voicemail')   updates.ship_status = 'voicemail';
      if (['no1','no2','no3'].includes(log.result)) updates.ship_status = log.result;
      if (log.reason) updates.ship_reason = log.reason;
      if (log.postpone_date) updates.followdate = log.postpone_date;

      await supabase.from('orders').update(updates).eq('id', log.order_id);
    }

    res.status(201).json({ log: data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
