const express = require('express');
const supabase = require('../config/supabase');
const { authMiddleware, adminOnly } = require('../middleware/auth');

const router = express.Router();
router.use(authMiddleware, adminOnly);

// GET /settings
router.get('/', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('settings')
      .select('key, value')
      .not('key', 'eq', 'admin_pass_hash'); // Ne jamais exposer le hash
    if (error) throw error;
    const map = {};
    data.forEach(row => { map[row.key] = row.value; });
    res.json({ settings: map });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /settings/:key
router.put('/:key', async (req, res) => {
  const { key } = req.params;
  const { value } = req.body;

  // Clés protégées
  if (key === 'admin_pass_hash') {
    return res.status(403).json({ error: 'Utilisez /auth/change-password' });
  }

  try {
    const { error } = await supabase
      .from('settings')
      .upsert({ key, value }, { onConflict: 'key' });
    if (error) throw error;
    res.json({ message: 'Paramètre mis à jour' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
