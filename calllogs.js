const { createClient } = require('@supabase/supabase-js');

// Client avec service_role — accès complet, utilisé côté serveur uniquement
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
  {
    auth: { persistSession: false }
  }
);

module.exports = supabase;
