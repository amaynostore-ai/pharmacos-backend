const express = require('express');
const bcrypt = require('bcryptjs');
const supabase = require('../config/supabase');
const { authMiddleware, adminOnly } = require('../middleware/auth');

const router = express.Router();
router.use(authMiddleware);

// ─── GET /agents ──────────────────────────────────────────────
// Admin: liste complète | Agent: uniquement ses infos
router.get('/', async (req, res) => {
  try {
    if (req.user.role === 'admin') {
      const { data, error } = await supabase
        .from('agents')
        .select('id, name, phone, active, target, created_at')
        .order('name');
      if (error) throw error;
      return res.json({ agents: data });
    } else {
      const { data, error } = await supabase
        .from('agents')
        .select('id, name, phone, target')
        .eq('id', req.user.id)
        .single();
      if (error) throw error;
      return res.json({ agents: [data] });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── POST /agents ─────────────────────────────────────────────
// Admin crée un agent (sans mot de passe — l'agent l'active lui-même)
router.post('/', adminOnly, async (req, res) => {
  const { name, phone, password, target } = req.body;
  if (!name) return res.status(400).json({ error: 'Nom obligatoire' });

  try {
    const agentData = {
      name,
      phone: phone || '',
      target: target || 30,
      active: true,
      pass_hash: password ? await bcrypt.hash(password, 12) : null,
    };

    const { data, error } = await supabase
      .from('agents').insert(agentData).select('id, name, phone, active, target').single();
    if (error) throw error;
    res.status(201).json({ agent: data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── PUT /agents/:id ──────────────────────────────────────────
router.put('/:id', adminOnly, async (req, res) => {
  const updates = { ...req.body };
  if (updates.password) {
    updates.pass_hash = await bcrypt.hash(updates.password, 12);
    delete updates.password;
  }
  delete updates.pass_hash; // sécurité — passer par /auth/change-password

  try {
    const { data, error } = await supabase
      .from('agents')
      .update(updates)
      .eq('id', req.params.id)
      .select('id, name, phone, active, target')
      .single();
    if (error) throw error;
    res.json({ agent: data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── DELETE /agents/:id ───────────────────────────────────────
router.delete('/:id', adminOnly, async (req, res) => {
  try {
    // Désactiver plutôt que supprimer (préserver l'historique)
    const { error } = await supabase
      .from('agents').update({ active: false }).eq('id', req.params.id);
    if (error) throw error;
    res.json({ message: 'Agent désactivé' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
