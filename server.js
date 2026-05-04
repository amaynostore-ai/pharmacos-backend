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
app.use(rateLimit({ windowMs: 10*60*1000, max: 200, message: { error: 'Trop de requêtes' } }));

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY, { auth: { persistSession: false } });

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

const loginLimit = rateLimit({ windowMs: 15*60*1000, max: 20, message: { error: 'Trop de tentatives' } });
const regLimit = rateLimit({ windowMs: 60*60*1000, max: 10, message: { error: 'Trop d inscriptions' } });

app.post('/api/auth/login', loginLimit, async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password || !role) return res.status(400).json({ error: 'Champs manquants' });
  try {
    if (role === 'admin') {
      // Check manager first
      if (username.toLowerCase() !== 'admin') {
        const { data: mgr } = await supabase.from('agents').select('id,name,pass_hash,active,role').ilike('name', username).single();
        if (mgr && mgr.role === 'manager') {
          if (!mgr.active) return res.status(403).json({ error: 'Compte désactivé' });
          if (!await bcrypt.compare(password, mgr.pass_hash)) return res.status(401).json({ error: 'Identifiants incorrects' });
          const token = jwt.sign({ id: mgr.id, name: mgr.name, role: 'manager' }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN||'8h' });
          return res.json({ token, user: { id: mgr.id, name: mgr.name, role: 'manager' } });
        }
        return res.status(401).json({ error: 'Identifiants incorrects' });
      }
      // Admin login - check ADMIN_PASSWORD env first
      const adminPass = process.env.ADMIN_PASSWORD || 'admin123';
      if (password === adminPass) {
        const token = jwt.sign({ id:'admin', name:'Admin', role:'admin' }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN||'8h' });
        return res.json({ token, user: { id:'admin', name:'Admin', role:'admin' } });
      }
      return res.status(401).json({ error: 'Identifiants incorrects' });
    } else {
      const { data: agent, error } = await supabase.from('agents').select('id,name,phone,pass_hash,active,role').ilike('name', username).single();
      if (error || !agent) return res.status(401).json({ error: 'Agent introuvable' });
      if (!agent.active) return res.status(403).json({ error: 'Compte désactivé' });
      if (!await bcrypt.compare(password, agent.pass_hash)) return res.status(401).json({ error: 'Mot de passe incorrect' });
      const agentRole = agent.role || 'agent';
      const token = jwt.sign({ id:agent.id, name:agent.name, role:agentRole }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN||'8h' });
      return res.json({ token, user: { id:agent.id, name:agent.name, role:agentRole, phone:agent.phone } });
    }
  } catch(e) { return res.status(500).json({ error: 'Erreur serveur' }); }
});

app.post('/api/auth/register-agent', regLimit, async (req, res) => {
  const { name, phone, password, activation_code } = req.body;
  if (!name||!phone||!password||!activation_code) return res.status(400).json({ error: 'Tous les champs sont obligatoires' });
  if (password.length < 4) return res.status(400).json({ error: 'Mot de passe trop court' });
  try {
    const activationCode = process.env.ACTIVATION_CODE || 'PHARMA2025';
    if (activation_code !== activationCode) return res.status(403).json({ error: "Code d activation incorrect" });
    const { data: agent, error } = await supabase.from('agents').select('id,name').ilike('name', name).single();
    if (error || !agent) return res.status(404).json({ error: 'Agent non trouvé' });
    const hash = await bcrypt.hash(password, 12);
    await supabase.from('agents').update({ pass_hash: hash, phone, active: true }).eq('id', agent.id);
    return res.json({ message: 'Compte activé avec succès' });
  } catch(e) { return res.status(500).json({ error: 'Erreur serveur' }); }
});

app.get('/api/auth/me', auth, (req, res) => res.json({ user: req.user }));

app.get('/api/orders', auth, async (req, res) => {
  try {
    let query = supabase.from('orders').select('*').order('created_at', { ascending: false });
    if (req.user.role === 'agent') query = query.eq('agent_name', req.user.name);
    const { data, error } = await query;
    if (error) throw error;
    res.json({ orders: data });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/orders', auth, async (req, res) => {
  try {
    const order = { ...req.body, agent_name: req.user.role==='agent'?req.user.name:(req.body.agent_name||'Admin'), created_at: new Date().toISOString(), ship_status:'pending', call_count:0 };
    if (!order.name || !order.phone) return res.status(400).json({ error: 'Nom et téléphone obligatoires' });
    const { data, error } = await supabase.from('orders').insert(order).select().single();
    if (error) throw error;
    res.status(201).json({ order: data });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/orders/:id', auth, async (req, res) => {
  try {
    if (req.user.role === 'agent') {
      const { data: ex } = await supabase.from('orders').select('agent_name').eq('id', req.params.id).single();
      if (!ex || ex.agent_name !== req.user.name) return res.status(403).json({ error: 'Accès refusé' });
    }
    const updates = { ...req.body, updated_at: new Date().toISOString() };
    if (req.user.role === 'agent') delete updates.agent_name;
    const { data, error } = await supabase.from('orders').update(updates).eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json({ order: data });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/orders/:id', auth, async (req, res) => {
  try {
    const { error } = await supabase.from('orders').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ message: 'Supprimé' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/agents', auth, async (req, res) => {
  try {
    if (req.user.role === 'admin' || req.user.role === 'manager') {
      const { data, error } = await supabase.from('agents').select('id,name,phone,active,target,role,created_at').eq('active',true).order('name');
      if (error) throw error;
      return res.json({ agents: data });
    } else {
      const { data, error } = await supabase.from('agents').select('id,name,phone,target').eq('id', req.user.id).single();
      if (error) throw error;
      return res.json({ agents: [data] });
    }
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/agents', auth, adminOnly, async (req, res) => {
  const { name, phone, password, target } = req.body;
  if (!name) return res.status(400).json({ error: 'Nom obligatoire' });
  try {
    const agentData = { name, phone:phone||'', target:target||30, active:true, pass_hash: password ? await bcrypt.hash(password,12) : null };
    const { data, error } = await supabase.from('agents').insert(agentData).select('id,name,phone,active,target').single();
    if (error) throw error;
    res.status(201).json({ agent: data });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/agents/:id', auth, adminOnly, async (req, res) => {
  try {
    const updates = { ...req.body };
    if (updates.password) { updates.pass_hash = await bcrypt.hash(updates.password, 12); delete updates.password; }
    const { data, error } = await supabase.from('agents').update(updates).eq('id', req.params.id).select('id,name,phone,active,target').single();
    if (error) throw error;
    res.json({ agent: data });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/agents/:id', auth, adminOnly, async (req, res) => {
  try {
    const { error } = await supabase.from('agents').update({ active: false }).eq('id', req.params.id);
    if (error) throw error;
    res.json({ message: 'Agent désactivé' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/calllogs', auth, async (req, res) => {
  try {
    let query = supabase.from('call_logs').select('*').order('created_at', { ascending: false }).limit(100);
    if (req.user.role === 'agent') query = query.eq('agent_name', req.user.name);
    const { data, error } = await query;
    if (error) throw error;
    res.json({ logs: data });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/calllogs', auth, async (req, res) => {
  try {
    const log = { ...req.body, agent_name: req.user.name, created_at: new Date().toISOString() };
    const { data, error } = await supabase.from('call_logs').insert(log).select().single();
    if (error) throw error;
    res.status(201).json({ log: data });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/settings', auth, adminOnly, async (req, res) => {
  try {
    const { data, error } = await supabase.from('settings').select('key,value').not('key','eq','admin_pass_hash');
    if (error) throw error;
    const map = {}; data.forEach(r => { map[r.key] = r.value; });
    res.json({ settings: map });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/settings/:key', auth, adminOnly, async (req, res) => {
  if (req.params.key === 'admin_pass_hash') return res.status(403).json({ error: 'Protégé' });
  try {
    const { error } = await supabase.from('settings').upsert({ key: req.params.key, value: req.body.value }, { onConflict: 'key' });
    if (error) throw error;
    res.json({ message: 'Mis à jour' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});


// PRODUCTS
app.get('/api/products', auth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('products').select('*').eq('active',true).order('name');
    if (error) throw error;
    res.json({ products: data });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/products', auth, adminOnly, async (req, res) => {
  try {
    const { data, error } = await supabase.from('products').insert(req.body).select().single();
    if (error) throw error;
    res.status(201).json({ product: data });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/products/:id', auth, adminOnly, async (req, res) => {
  try {
    const { data, error } = await supabase.from('products').update(req.body).eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json({ product: data });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/products/:id', auth, adminOnly, async (req, res) => {
  try {
    const { error } = await supabase.from('products').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ message: 'Supprimé' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// RETURNS
app.get('/api/returns', auth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('returns').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    res.json({ returns: data });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/returns', auth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('returns').insert({ ...req.body, date: new Date().toISOString().split('T')[0] }).select().single();
    if (error) throw error;
    // Update product qty
    if (req.body.product && req.body.qty) {
      const { data: prod } = await supabase.from('products').select('id,qty').ilike('name', req.body.product).single();
      if (prod) await supabase.from('products').update({ qty: prod.qty + (req.body.qty||1) }).eq('id', prod.id);
    }
    res.status(201).json({ return: data });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// BLACKLIST
app.get('/api/blacklist', auth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('blacklist').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    res.json({ blacklist: data });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/blacklist', auth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('blacklist').insert({ ...req.body, date: new Date().toISOString().split('T')[0] }).select().single();
    if (error) throw error;
    res.status(201).json({ item: data });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/blacklist/:id', auth, async (req, res) => {
  try {
    const { error } = await supabase.from('blacklist').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ message: 'Supprimé' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});


// PRODUCTS
app.get('/api/products', auth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('products').select('*').eq('active',true).order('name');
    if (error) throw error;
    res.json({ products: data });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/products', auth, adminOnly, async (req, res) => {
  try {
    const { data, error } = await supabase.from('products').insert(req.body).select().single();
    if (error) throw error;
    res.status(201).json({ product: data });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/products/:id', auth, adminOnly, async (req, res) => {
  try {
    const { data, error } = await supabase.from('products').update(req.body).eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json({ product: data });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/products/:id', auth, adminOnly, async (req, res) => {
  try {
    const { error } = await supabase.from('products').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ message: 'Supprimé' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// RETURNS
app.get('/api/returns', auth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('returns').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    res.json({ returns: data });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/returns', auth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('returns').insert(req.body).select().single();
    if (error) throw error;
    res.status(201).json({ return: data });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// BLACKLIST
app.get('/api/blacklist', auth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('blacklist').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    res.json({ blacklist: data });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/blacklist', auth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('blacklist').insert(req.body).select().single();
    if (error) throw error;
    res.status(201).json({ item: data });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/blacklist/:id', auth, async (req, res) => {
  try {
    const { error } = await supabase.from('blacklist').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ message: 'Supprimé' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));
app.use((req, res) => res.status(404).json({ error: 'Route introuvable' }));
app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: 'Erreur interne' }); });

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Pharmacos CRM Backend port ${PORT}`));
