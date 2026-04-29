const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const supabase = require('../config/supabase');
const { authMiddleware, adminOnly } = require('../middleware/auth');

const router = express.Router();

// Rate limiter strict sur le login — anti brute-force
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,                    // max 10 tentatives
  message: { error: 'Trop de tentatives. Réessayez dans 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Rate limiter sur l'inscription
const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 heure
  max: 5,
  message: { error: 'Trop d\'inscriptions depuis cette IP.' },
});

// ─── POST /auth/login ───────────────────────────────────────
router.post('/login', loginLimiter, async (req, res) => {
  const { username, password, role } = req.body;

  if (!username || !password || !role) {
    return res.status(400).json({ error: 'Champs manquants' });
  }

  try {
    if (role === 'admin') {
      // Vérification admin depuis la table settings
      const { data: settings } = await supabase
        .from('settings')
        .select('value')
        .eq('key', 'admin_pass_hash')
        .single();

      if (!settings) return res.status(401).json({ error: 'Admin non configuré' });

      const match = await bcrypt.compare(password, settings.value);
      if (!match || username !== 'admin') {
        return res.status(401).json({ error: 'Identifiants incorrects' });
      }

      const token = jwt.sign(
        { id: 'admin', name: 'Admin', role: 'admin' },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN || '8h' }
      );

      return res.json({
        token,
        user: { id: 'admin', name: 'Admin', role: 'admin' }
      });

    } else {
      // Connexion agent
      const { data: agent, error } = await supabase
        .from('agents')
        .select('id, name, phone, pass_hash, active')
        .ilike('name', username)
        .single();

      if (error || !agent) {
        return res.status(401).json({ error: 'Agent introuvable' });
      }

      if (!agent.active) {
        return res.status(403).json({ error: 'Compte désactivé, contactez l\'admin' });
      }

      const match = await bcrypt.compare(password, agent.pass_hash);
      if (!match) {
        return res.status(401).json({ error: 'Mot de passe incorrect' });
      }

      const token = jwt.sign(
        { id: agent.id, name: agent.name, role: 'agent' },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN || '8h' }
      );

      return res.json({
        token,
        user: { id: agent.id, name: agent.name, role: 'agent', phone: agent.phone }
      });
    }
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ─── POST /auth/register-agent ──────────────────────────────
// Activation du compte agent (l'agent crée son mot de passe)
router.post('/register-agent', registerLimiter, async (req, res) => {
  const { name, phone, password, activation_code } = req.body;

  if (!name || !phone || !password || !activation_code) {
    return res.status(400).json({ error: 'Tous les champs sont obligatoires' });
  }

  if (password.length < 4) {
    return res.status(400).json({ error: 'Mot de passe trop court (min 4)' });
  }

  try {
    // Vérifier le code d'activation
    const { data: setting } = await supabase
      .from('settings')
      .select('value')
      .eq('key', 'activation_code')
      .single();

    if (!setting || activation_code !== setting.value) {
      return res.status(403).json({ error: 'Code d\'activation incorrect' });
    }

    // Trouver l'agent par nom (créé par l'admin)
    const { data: agent, error } = await supabase
      .from('agents')
      .select('id, name, pass_hash')
      .ilike('name', name)
      .single();

    if (error || !agent) {
      return res.status(404).json({ error: 'Agent non trouvé — demandez à l\'admin de vous ajouter' });
    }

    // Hacher et sauvegarder le mot de passe
    const hash = await bcrypt.hash(password, 12);
    await supabase
      .from('agents')
      .update({ pass_hash: hash, phone, active: true })
      .eq('id', agent.id);

    return res.json({ message: 'Compte activé avec succès' });

  } catch (err) {
    console.error('Register error:', err);
    return res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ─── POST /auth/change-password ─────────────────────────────
router.post('/change-password', authMiddleware, async (req, res) => {
  const { old_password, new_password } = req.body;

  if (!old_password || !new_password || new_password.length < 4) {
    return res.status(400).json({ error: 'Données invalides' });
  }

  try {
    if (req.user.role === 'admin') {
      const { data: settings } = await supabase
        .from('settings').select('value').eq('key', 'admin_pass_hash').single();
      const match = await bcrypt.compare(old_password, settings.value);
      if (!match) return res.status(401).json({ error: 'Ancien mot de passe incorrect' });
      const hash = await bcrypt.hash(new_password, 12);
      await supabase.from('settings').update({ value: hash }).eq('key', 'admin_pass_hash');
    } else {
      const { data: agent } = await supabase
        .from('agents').select('pass_hash').eq('id', req.user.id).single();
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

// ─── GET /auth/me ────────────────────────────────────────────
router.get('/me', authMiddleware, (req, res) => {
  res.json({ user: req.user });
});

module.exports = router;
