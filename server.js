require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(helmet());
app.set('trust proxy', 1);
app.use(cors({ origin: '*', methods: ['GET','POST','PUT','DELETE'], allowedHeaders: ['Content-Type','Authorization'] }));
app.use(express.json({ limit: '2mb' }));

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY, { auth: { persistSession: false } });

// ─── Rate limiters ───────────────────────────────────────────
const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  message: { error: 'Trop de requêtes, attendez 1 minute' },
  standardHeaders: true,
  legacyHeaders: false,
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 200,
  message: { error: 'Trop de requêtes' },
  standardHeaders: true,
  legacyHeaders: false,
});

const regLimit = rateLimit({ windowMs: 60*60*1000, max: 10, message: { error: 'Trop d inscriptions' } });

app.use('/api/auth/login', loginLimiter);
app.use('/api/', apiLimiter);

// ─── Middleware auth ─────────────────────────────────────────
function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) return res.status(401).json({ error: 'Token manquant' });
  try { req.user = jwt.verify(h.split(' ')[1], process.env.JWT_SECRET); next(); }
  catch(e) { return res.status(401).json({ error: 'Token invalide' }); }
}
function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin uniquement' });
  next();
}

// ─── POST /api/auth/login ────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password || !role) return res.status(400).json({ error: 'Champs manquants' });
  try {
    if (role === 'admin') {
      if (username.toLowerCase() !== 'admin') {
        const { data: mgr } = await supabase.from('agents').select('id,name,pass_hash,active,role').ilike('name', username).single();
        if (mgr && mgr.role === 'manager') {
          if (!mgr.active) return res.status(403).json({ error: 'Compte désactivé' });
          const match = await bcrypt.compare(password, mgr.pass_hash);
          if (!match) return res.status(401).json({ error: 'Identifiants incorrects' });
          const token = jwt.sign({ id: mgr.id, name: mgr.name, role: 'admin' }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '8h' });
          return res.json({ token, user: { id: mgr.id, name: mgr.name, role: 'admin' } });
        }
        return res.status(401).json({ error: 'Identifiants incorrects' });
      }
      const { data: settings } = await supabase.from('settings').select('value').eq('key', 'admin_pass_hash').single();
      if (!settings) return res.status(401).json({ error: 'Admin non configuré' });
      const match = await bcrypt.compare(password, settings.value);
      if (!match) return res.status(401).json({ error: 'Identifiants incorrects' });
      const token = jwt.sign({ id: 'admin', name: 'Admin', role: 'admin' }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '8h' });
      return res.json({ token, user: { id: 'admin', name: 'Admin', role: 'admin' } });
    } else {
      const { data: agent, error } = await supabase.from('agents').select('id,name,phone,pass_hash,active').ilike('name', username).single();
      if (error || !agent) return res.status(401).json({ error: 'Agent introuvable' });
      if (!agent.active) return res.status(403).json({ error: 'Compte désactivé, contactez l\'admin' });
      const match = await bcrypt.compare(password, agent.pass_hash);
      if (!match) return res.status(401).json({ error: 'Mot de passe incorrect' });
      const token = jwt.sign({ id: agent.id, name: agent.name, role: 'agent' }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '8h' });
      return res.json({ token, user: { id: agent.id, name: agent.name, role: 'agent', phone: agent.phone } });
    }
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ─── POST /api/auth/register-agent ──────────────────────────
app.post('/api/auth/register-agent', regLimit, async (req, res) => {
  const { name, phone, password, activation_code } = req.body;
  if (!name || !phone || !password || !activation_code) return res.status(400).json({ error: 'Tous les champs sont obligatoires' });
  if (password.length < 4) return res.status(400).json({ error: 'Mot de passe trop court (min 4)' });
  try {
    const { data: setting } = await supabase.from('settings').select('value').eq('key', 'activation_code').single();
    if (!setting || activation_code !== setting.value) return res.status(403).json({ error: 'Code d\'activation incorrect' });
    const { data: agent, error } = await supabase.from('agents').select('id,name,pass_hash').ilike('name', name).single();
    if (error || !agent) return res.status(404).json({ error: 'Agent non trouvé — demandez à l\'admin de vous ajouter' });
    const hash = await bcrypt.hash(password, 12);
    await supabase.from('agents').update({ pass_hash: hash, phone, active: true }).eq('id', agent.id);
    return res.json({ message: 'Compte activé avec succès' });
  } catch (err) {
    console.error('Register error:', err);
    return res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ─── GET /api/auth/me ────────────────────────────────────────
app.get('/api/auth/me', auth, (req, res) => {
  res.json({ user: req.user });
});

// ─── POST /api/auth/change-password ─────────────────────────
app.post('/api/auth/change-password', auth, async (req, res) => {
  const { old_password, new_password } = req.body;
  if (!old_password || !new_password || new_password.length < 4) return res.status(400).json({ error: 'Données invalides' });
  try {
    if (req.user.role === 'admin') {
      const { data: settings } = await supabase.from('settings').select('value').eq('key', 'admin_pass_hash').single();
      const match = await bcrypt.compare(old_password, settings.value);
      if (!match) return res.status(401).json({ error: 'Ancien mot de passe incorrect' });
      const hash = await bcrypt.hash(new_password, 12);
      await supabase.from('settings').update({ value: hash }).eq('key', 'admin_pass_hash');
    } else {
      const { data: agent } = await supabase.from('agents').select('pass_hash').eq('id', req.user.id).single();
      const match = await bcrypt.compare(old_password, agent.pass_hash);
      if (!match) return res.status(401).json({ error: 'Ancien mot de passe incorrect' });
      const hash = await bcrypt.hash(new_password, 12);
      await supabase.from('agents').update({ pass_hash: hash }).eq('id', req.user.id);
    }
    return res.json({ message: 'Mot de passe mis à jour' });
  } catch (err) {
    return res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ─── GET /api/orders ─────────────────────────────────────────
app.get('/api/orders', auth, async (req, res) => {
  try {
    let query = supabase.from('orders').select('*').order('created_at', { ascending: false }).limit(500);
    if (req.user.role === 'agent') query = query.eq('agent_name', req.user.name);
    if (req.query.status) query = query.eq('status', req.query.status);
    if (req.query.city) query = query.eq('city', req.query.city);
    if (req.query.agent && req.user.role === 'admin') query = query.eq('agent_name', req.query.agent);
    if (req.query.q) {
      const q = req.query.q;
      query = query.or(`name.ilike.%${q}%,phone.ilike.%${q}%,track.ilike.%${q}%`);
    }
    const { data, error } = await query;
    if (error) throw error;
    res.json({ orders: data });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── POST /api/orders ────────────────────────────────────────
app.post('/api/orders', auth, async (req, res) => {
  try {
    const order = {
      ...req.body,
      agent_name: req.user.role === 'admin' ? (req.body.agent_name || 'Admin') : req.user.name,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      ship_status: req.body.ship_status || 'pending',
    };
    if (!order.name || !order.phone) return res.status(400).json({ error: 'Nom et téléphone obligatoires' });
    const { data, error } = await supabase.from('orders').insert(order).select().single();
    if (error) throw error;
    res.status(201).json({ order: data });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── PUT /api/orders/:id ─────────────────────────────────────
app.put('/api/orders/:id', auth, async (req, res) => {
  try {
    const { id } = req.params;
    if (req.user.role === 'agent') {
      const { data: existing } = await supabase.from('orders').select('agent_name').eq('id', id).single();
      if (!existing || existing.agent_name !== req.user.name) return res.status(403).json({ error: 'Accès refusé' });
    }
    const updates = { ...req.body };
    if (req.user.role === 'agent') delete updates.agent_name;
    updates.updated_at = new Date().toISOString();
    delete updates.id; delete updates.created_at;
    const { data, error } = await supabase.from('orders').update(updates).eq('id', id).select().single();
    if (error) throw error;
    res.json({ order: data });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── DELETE /api/orders/:id ──────────────────────────────────
app.delete('/api/orders/:id', auth, async (req, res) => {
  try {
    const { id } = req.params;
    if (req.user.role === 'agent') {
      const { data: existing } = await supabase.from('orders').select('agent_name').eq('id', id).single();
      if (!existing || existing.agent_name !== req.user.name) return res.status(403).json({ error: 'Accès refusé' });
    }
    const { error } = await supabase.from('orders').delete().eq('id', id);
    if (error) throw error;
    res.json({ message: 'Supprimé' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── GET /api/orders/stats/summary ───────────────────────────
app.get('/api/orders/stats/summary', auth, async (req, res) => {
  try {
    let query = supabase.from('orders').select('status, price, ship_status, agent_name, created_at');
    if (req.user.role === 'agent') query = query.eq('agent_name', req.user.name);
    const { data, error } = await query;
    if (error) throw error;
    const total = data.length;
    const confirmed = data.filter(o => o.status === 'مؤكد').length;
    const cancelled = data.filter(o => o.status === 'ملغى').length;
    const revenue = data.filter(o => o.status === 'مؤكد').reduce((s, o) => s + (o.price || 0), 0);
    const delivered = data.filter(o => o.ship_status === 'delivered').length;
    const inTransit = data.filter(o => ['pending','ready'].includes(o.ship_status)).length;
    res.json({ total, confirmed, cancelled, revenue, delivered, inTransit, rate: total ? Math.round(confirmed / total * 100) : 0 });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── GET /api/agents ─────────────────────────────────────────
app.get('/api/agents', auth, adminOnly, async (req, res) => {
  try {
    const { data, error } = await supabase.from('agents').select('id,name,phone,active,role,created_at').order('created_at', { ascending: false });
    if (error) throw error;
    res.json({ agents: data });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── POST /api/agents ────────────────────────────────────────
app.post('/api/agents', auth, adminOnly, async (req, res) => {
  try {
    const { name, phone, role: agentRole } = req.body;
    if (!name) return res.status(400).json({ error: 'Nom obligatoire' });
    const { data, error } = await supabase.from('agents').insert({ name, phone, role: agentRole || 'agent', active: false }).select().single();
    if (error) throw error;
    res.status(201).json({ agent: data });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── PUT /api/agents/:id ─────────────────────────────────────
app.put('/api/agents/:id', auth, adminOnly, async (req, res) => {
  try {
    const { id } = req.params;
    const updates = { ...req.body };
    delete updates.id; delete updates.pass_hash;
    const { data, error } = await supabase.from('agents').update(updates).eq('id', id).select().single();
    if (error) throw error;
    res.json({ agent: data });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── DELETE /api/agents/:id ──────────────────────────────────
app.delete('/api/agents/:id', auth, adminOnly, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = await supabase.from('agents').delete().eq('id', id);
    if (error) throw error;
    res.json({ message: 'Agent supprimé' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── GET /api/calllogs ───────────────────────────────────────
app.get('/api/calllogs', auth, async (req, res) => {
  try {
    let query = supabase.from('calllogs').select('*').order('created_at', { ascending: false }).limit(200);
    if (req.user.role === 'agent') query = query.eq('agent_name', req.user.name);
    if (req.query.order_id) query = query.eq('order_id', req.query.order_id);
    const { data, error } = await query;
    if (error) throw error;
    res.json({ calllogs: data });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── POST /api/calllogs ──────────────────────────────────────
app.post('/api/calllogs', auth, async (req, res) => {
  try {
    const log = { ...req.body, agent_name: req.user.name, created_at: new Date().toISOString() };
    const { data, error } = await supabase.from('calllogs').insert(log).select().single();
    if (error) throw error;
    res.status(201).json({ calllog: data });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── GET /api/settings ───────────────────────────────────────
app.get('/api/settings', auth, adminOnly, async (req, res) => {
  try {
    const { data, error } = await supabase.from('settings').select('key, value').not('key', 'eq', 'admin_pass_hash');
    if (error) throw error;
    const map = {};
    data.forEach(row => { map[row.key] = row.value; });
    res.json({ settings: map });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── PUT /api/settings/:key ──────────────────────────────────
app.put('/api/settings/:key', auth, adminOnly, async (req, res) => {
  const { key } = req.params;
  const { value } = req.body;
  if (key === 'admin_pass_hash') return res.status(403).json({ error: 'Utilisez /auth/change-password' });
  try {
    const { error } = await supabase.from('settings').upsert({ key, value }, { onConflict: 'key' });
    if (error) throw error;
    res.json({ message: 'Paramètre mis à jour' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── GET /api/products ───────────────────────────────────────
app.get('/api/products', auth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('products').select('*').order('name');
    if (error) throw error;
    res.json({ products: data });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── POST /api/products ──────────────────────────────────────
app.post('/api/products', auth, adminOnly, async (req, res) => {
  try {
    const { data, error } = await supabase.from('products').insert(req.body).select().single();
    if (error) throw error;
    res.status(201).json({ product: data });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── PUT /api/products/:id ───────────────────────────────────
app.put('/api/products/:id', auth, adminOnly, async (req, res) => {
  try {
    const { id } = req.params;
    const { data, error } = await supabase.from('products').update(req.body).eq('id', id).select().single();
    if (error) throw error;
    res.json({ product: data });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── DELETE /api/products/:id ────────────────────────────────
app.delete('/api/products/:id', auth, adminOnly, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = await supabase.from('products').delete().eq('id', id);
    if (error) throw error;
    res.json({ message: 'Produit supprimé' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── GET /api/returns ────────────────────────────────────────
app.get('/api/returns', auth, async (req, res) => {
  try {
    let query = supabase.from('returns').select('*').order('created_at', { ascending: false });
    if (req.user.role === 'agent') query = query.eq('agent_name', req.user.name);
    const { data, error } = await query;
    if (error) throw error;
    res.json({ returns: data });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── POST /api/returns ───────────────────────────────────────
app.post('/api/returns', auth, async (req, res) => {
  try {
    const ret = { ...req.body, agent_name: req.user.name, created_at: new Date().toISOString() };
    const { data, error } = await supabase.from('returns').insert(ret).select().single();
    if (error) throw error;
    res.status(201).json({ return: data });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── GET /api/blacklist ──────────────────────────────────────
app.get('/api/blacklist', auth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('blacklist').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    res.json({ blacklist: data });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── POST /api/blacklist ─────────────────────────────────────
app.post('/api/blacklist', auth, adminOnly, async (req, res) => {
  try {
    const { data, error } = await supabase.from('blacklist').insert({ ...req.body, created_at: new Date().toISOString() }).select().single();
    if (error) throw error;
    res.status(201).json({ entry: data });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── DELETE /api/blacklist/:id ───────────────────────────────
app.delete('/api/blacklist/:id', auth, adminOnly, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = await supabase.from('blacklist').delete().eq('id', id);
    if (error) throw error;
    res.json({ message: 'Supprimé de la liste noire' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── GET /api/health ─────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ─── Error handler ───────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: 'Route introuvable' }));
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Erreur interne' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Pharmacos CRM backend running on port ${PORT}`));
