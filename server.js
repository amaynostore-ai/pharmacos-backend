// ضيف هاد الكود في بداية server.js بعد const app = express()

// ===== RATE LIMIT FIX =====
const rateLimit = require('express-rate-limit');

// Login: 20 محاولة في الدقيقة
const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  message: { error: 'Trop de requêtes, attendez 1 minute' },
  standardHeaders: true,
  legacyHeaders: false,
});

// باقي الـ API: 200 request في الدقيقة
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 200,
  message: { error: 'Trop de requêtes' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/auth/login', loginLimiter);
app.use('/api/', apiLimiter);
// ===========================
