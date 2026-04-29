# ============================================================
# Pharmacos CRM - Variables d'environnement
# Copier ce fichier en .env et remplir les valeurs
# ============================================================

# Supabase (https://supabase.com -> Settings -> API)
SUPABASE_URL=https://XXXXXXXXXXXXXXXX.supabase.co
SUPABASE_SERVICE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6...   # service_role key (secret!)

# JWT Secret - Générer avec: node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
JWT_SECRET=remplacer_par_une_chaine_aleatoire_longue_et_securisee

# Durée de session
JWT_EXPIRES_IN=8h

# Port du serveur
PORT=3000

# Environnement
NODE_ENV=production

# CORS - URL du frontend (GitHub Pages ou Netlify)
FRONTEND_URL=https://TON_USERNAME.github.io
