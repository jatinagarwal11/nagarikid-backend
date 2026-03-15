require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3001;

/* ═════════════════════════════════════════════════════════
   Helpers
   ═════════════════════════════════════════════════════════ */

function computeAge(dob) {
  const b = new Date(dob);
  const n = new Date();
  let age = n.getFullYear() - b.getFullYear();
  const m = n.getMonth() - b.getMonth();
  if (m < 0 || (m === 0 && n.getDate() < b.getDate())) age--;
  return age;
}

function decodeCitizenJwt(req) {
  const h = req.headers.authorization;
  if (!h) return null;
  try {
    const d = jwt.verify(h.split(' ')[1], process.env.JWT_SECRET);
    if (d.type === 'verifier' || d.type === 'admin') return null;
    return d;
  } catch { return null; }
}

function decodeVerifierJwt(req) {
  const h = req.headers.authorization;
  if (!h) return null;
  try {
    const d = jwt.verify(h.split(' ')[1], process.env.JWT_SECRET);
    return d.type === 'verifier' ? d : null;
  } catch { return null; }
}

function decodeAdminJwt(req) {
  const h = req.headers.authorization;
  if (!h) return null;
  try {
    const d = jwt.verify(h.split(' ')[1], process.env.JWT_SECRET);
    return d.type === 'admin' ? d : null;
  } catch { return null; }
}

function purposeFor(bt) {
  if (bt === 'bank') return 'KYC identity verification';
  if (bt === 'pharmacy') return 'Restricted drug eligibility check';
  return 'Age verification';
}

async function logAudit(citizenId, verifier, purpose, decision, fields, reason) {
  await supabase.from('audit_trail').insert({
    citizen_id: citizenId || null,
    verifier_org_id: verifier.id,
    verifier_user: verifier.company_name,
    business_type: verifier.business_type,
    purpose,
    fields_accessed: JSON.stringify(fields),
    decision,
    reason: reason || null,
  });
}

async function checkBruteForce(verifierOrgId) {
  const windowMin = 5;
  const threshold = 10;
  const since = new Date(Date.now() - windowMin * 60000).toISOString();
  const { count } = await supabase
    .from('audit_trail')
    .select('*', { count: 'exact', head: true })
    .eq('verifier_org_id', verifierOrgId)
    .gte('timestamp', since);
  if (count >= threshold) {
    await supabase.from('suspicious_activity').insert({
      verifier_org_id: verifierOrgId,
      activity_type: 'brute_force',
      description: `${count} verification attempts in ${windowMin} minutes`,
      request_count: count,
      time_window_minutes: windowMin,
    });
    // also mark latest audit rows as suspicious
    const { data: recent } = await supabase
      .from('audit_trail')
      .select('id')
      .eq('verifier_org_id', verifierOrgId)
      .gte('timestamp', since)
      .order('timestamp', { ascending: false })
      .limit(count);
    if (recent && recent.length) {
      const ids = recent.map(r => r.id);
      await supabase.from('audit_trail').update({ is_suspicious: true }).in('id', ids);
    }
    return true;
  }
  return false;
}

function buildResponse(user, profile, businessType) {
  const age = computeAge(user.dob);
  const addr = profile
    ? `Ward ${profile.ward}, ${profile.municipality}, ${profile.district}, ${profile.province}`
    : 'N/A';

  if (businessType === 'bank') {
    const approved = profile && profile.kyc_verified;
    return {
      verified: true,
      business_type: 'bank',
      decision: approved ? 'approved' : 'denied',
      reason: approved ? 'KYC verified' : 'KYC not yet verified for this citizen',
      data: {
        full_name: user.name,
        dob: user.dob,
        age,
        national_id: user.national_id,
        address: addr,
        photo_url: user.photo_url,
        identity_verified: true,
        liveness_verified: true,
        kyc_status: approved ? 'verified' : 'unverified',
        kyc_risk_level: profile ? profile.kyc_risk_level : 'pending',
        citizenship_number: profile ? profile.citizenship_number : 'N/A',
      },
    };
  }

  if (businessType === 'pharmacy') {
    const prescriptionValid = profile && profile.has_valid_prescription
      && new Date(profile.prescription_expiry) > new Date();
    const allowedDrugs = (profile && profile.allowed_drugs) || [];
    const approved = prescriptionValid && allowedDrugs.length > 0;
    return {
      verified: true,
      business_type: 'pharmacy',
      decision: approved ? 'approved' : 'denied',
      reason: approved
        ? `Authorised for ${allowedDrugs.length} restricted drug${allowedDrugs.length > 1 ? ' categories' : ''}`
        : !prescriptionValid ? 'Prescription invalid or expired' : 'No restricted drugs authorised',
      data: {
        full_name: user.name,
        age,
        prescription_status: prescriptionValid ? 'valid' : 'invalid / expired',
        prescription_expiry: profile ? profile.prescription_expiry : null,
        allowed_drugs: allowedDrugs,
        doctor_authorization: profile ? profile.doctor_authorization : null,
        recent_drug_flag: profile && profile.recent_drug_purchase_date
          ? (Date.now() - new Date(profile.recent_drug_purchase_date).getTime()) < 7 * 86400000
          : false,
      },
    };
  }

  // age_verification
  return {
    verified: true,
    business_type: 'age_verification',
    decision: age >= 18 ? 'approved' : 'denied',
    reason: age >= 18 ? 'Age threshold met' : 'Under 18',
    data: {
      age_verified: true,
      over_18: age >= 18,
      over_21: age >= 21,
      liveness_verified: true,
    },
  };
}

/* ═════════════════════════════════════════════════════════
   Health
   ═════════════════════════════════════════════════════════ */
app.get('/', (req, res) => {
  res.json({ message: 'NagarikID Backend API', status: 'running' });
});

/* ═════════════════════════════════════════════════════════
   Citizen auth
   ═════════════════════════════════════════════════════════ */
app.post('/login', async (req, res) => {
  const { national_id, password } = req.body;
  const { data, error } = await supabase
    .from('users').select('*').eq('national_id', national_id).single();
  if (error || !data) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, data.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign(
    { id: data.id, national_id: data.national_id, type: 'citizen' },
    process.env.JWT_SECRET,
    { expiresIn: '1h' },
  );
  res.json({ token });
});

app.post('/register', async (req, res) => {
  const { national_id, name, dob, photo_url, password } = req.body;
  const { data: existing } = await supabase
    .from('users').select('id').eq('national_id', national_id).single();
  if (existing) return res.status(400).json({ error: 'User with this National ID already exists' });

  const password_hash = await bcrypt.hash(password, 10);
  const { data, error } = await supabase
    .from('users')
    .insert({ national_id, name, dob, photo_url, password_hash })
    .select().single();
  if (error) { console.error('Registration error:', error); return res.status(500).json({ error: 'Failed to register user' }); }

  // auto-create blank citizen profile
  await supabase.from('citizen_profiles').insert({ user_id: data.id });

  res.json({ message: 'User registered successfully', user: data });
});

app.get('/generate-token', (req, res) => {
  const d = decodeCitizenJwt(req);
  if (!d) return res.status(401).json({ error: 'Invalid token' });
  const uid = d.national_id;
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = crypto.randomBytes(4).toString('hex');
  const raw = uid + timestamp + nonce;
  const hmac = crypto.createHmac('sha256', process.env.HMAC_SECRET).update(raw).digest('hex');
  res.json({ uid, timestamp, nonce, token: hmac });
});

app.get('/user', async (req, res) => {
  const d = decodeCitizenJwt(req);
  if (!d) return res.status(401).json({ error: 'Invalid token' });
  const { data, error } = await supabase
    .from('users').select('name, national_id, dob, photo_url').eq('id', d.id).single();
  if (error) return res.status(404).json({ error: 'User not found' });
  res.json(data);
});

/* ═════════════════════════════════════════════════════════
   Citizen — extended profile, knowledge graph, audit trail
   ═════════════════════════════════════════════════════════ */
app.get('/citizen/profile', async (req, res) => {
  const d = decodeCitizenJwt(req);
  if (!d) return res.status(401).json({ error: 'Auth required' });
  const { data: user } = await supabase.from('users').select('*').eq('id', d.id).single();
  const { data: profile } = await supabase.from('citizen_profiles').select('*').eq('user_id', d.id).single();
  if (!user) return res.status(404).json({ error: 'Not found' });
  res.json({ user, profile });
});

app.get('/citizen/knowledge-graph', async (req, res) => {
  const d = decodeCitizenJwt(req);
  if (!d) return res.status(401).json({ error: 'Auth required' });
  const { data: user } = await supabase.from('users').select('*').eq('id', d.id).single();
  const { data: profile } = await supabase.from('citizen_profiles').select('*').eq('user_id', d.id).single();
  const { count: auditCount } = await supabase
    .from('audit_trail').select('*', { count: 'exact', head: true }).eq('citizen_id', d.id);
  const { data: lastAudit } = await supabase
    .from('audit_trail').select('timestamp').eq('citizen_id', d.id)
    .order('timestamp', { ascending: false }).limit(1);

  const age = computeAge(user.dob);
  const p = profile || {};
  const nodes = [
    { id: 'identity', label: 'Core Identity', data: { name: user.name, national_id: user.national_id, dob: user.dob, age, gender: p.gender || 'N/A', photo_url: user.photo_url } },
    { id: 'kyc', label: 'KYC', data: { status: p.kyc_verified ? 'Verified' : 'Unverified', verified_date: p.kyc_verified_date, risk_level: p.kyc_risk_level || 'pending' } },
    { id: 'address', label: 'Address', data: { province: p.province, district: p.district, municipality: p.municipality, ward: p.ward } },
    { id: 'prescriptions', label: 'Drug Permissions', data: { has_valid_prescription: p.has_valid_prescription || false, expiry: p.prescription_expiry, allowed_drugs: p.allowed_drugs || [], doctor: p.doctor_authorization } },
    { id: 'vehicles', label: 'Vehicles', data: { license: p.license_number || 'None', registration: p.vehicle_registration || 'None' } },
    { id: 'audit', label: 'Access History', data: { total_accesses: auditCount || 0, last_access: lastAudit && lastAudit[0] ? lastAudit[0].timestamp : 'Never' } },
  ];
  const edges = nodes.filter(n => n.id !== 'identity').map(n => ({ from: 'identity', to: n.id }));
  res.json({ nodes, edges });
});

app.get('/citizen/audit-trail', async (req, res) => {
  const d = decodeCitizenJwt(req);
  if (!d) return res.status(401).json({ error: 'Auth required' });
  const { data: entries } = await supabase
    .from('audit_trail')
    .select('*, verifier_organizations(company_name, company_pan, business_type)')
    .eq('citizen_id', d.id)
    .order('timestamp', { ascending: false });
  res.json(entries || []);
});

/* ═════════════════════════════════════════════════════════
   Verifier auth
   ═════════════════════════════════════════════════════════ */
app.post('/verifier/login', async (req, res) => {
  const { company_pan, password } = req.body;
  const { data, error } = await supabase
    .from('verifier_organizations').select('*')
    .eq('company_pan', company_pan).eq('status', 'approved').single();
  if (error || !data) return res.status(401).json({ error: 'Invalid PAN or credentials' });
  const ok = await bcrypt.compare(password, data.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign(
    { id: data.id, company_pan: data.company_pan, business_type: data.business_type, company_name: data.company_name, type: 'verifier' },
    process.env.JWT_SECRET,
    { expiresIn: '8h' },
  );
  res.json({ token, business_type: data.business_type, company_name: data.company_name });
});

app.get('/verifier/profile', async (req, res) => {
  const v = decodeVerifierJwt(req);
  if (!v) return res.status(401).json({ error: 'Auth required' });
  const { data } = await supabase
    .from('verifier_organizations').select('*').eq('id', v.id).single();
  res.json(data);
});

app.get('/verifier/audit-trail', async (req, res) => {
  const v = decodeVerifierJwt(req);
  if (!v) return res.status(401).json({ error: 'Auth required' });
  const { data } = await supabase
    .from('audit_trail')
    .select('*')
    .eq('verifier_org_id', v.id)
    .order('timestamp', { ascending: false });
  res.json(data || []);
});

/* ═════════════════════════════════════════════════════════
   Verify — role-filtered with audit + brute-force check
   ═════════════════════════════════════════════════════════ */
app.post('/verify', async (req, res) => {
  const v = decodeVerifierJwt(req);
  if (!v) return res.status(401).json({ error: 'Verifier authentication required' });

  const { uid, timestamp, nonce, token } = req.body;
  const current = Math.floor(Date.now() / 1000);

  // expired token
  if (current - timestamp > 10) {
    await logAudit(null, v, purposeFor(v.business_type), 'denied', [], 'QR token expired');
    await checkBruteForce(v.id);
    return res.json({ verified: false, reason: 'QR token expired' });
  }

  // invalid HMAC
  const raw = uid + timestamp + nonce;
  const expected = crypto.createHmac('sha256', process.env.HMAC_SECRET).update(raw).digest('hex');
  if (token !== expected) {
    await logAudit(null, v, purposeFor(v.business_type), 'denied', [], 'Invalid QR token');
    await checkBruteForce(v.id);
    return res.json({ verified: false, reason: 'Invalid QR token' });
  }

  // look up citizen
  const { data: user } = await supabase
    .from('users').select('*').eq('national_id', uid).single();
  if (!user) {
    await logAudit(null, v, purposeFor(v.business_type), 'denied', [], 'Citizen not found');
    await checkBruteForce(v.id);
    return res.json({ verified: false, reason: 'Citizen not found' });
  }

  const { data: profile } = await supabase
    .from('citizen_profiles').select('*').eq('user_id', user.id).single();

  // get policy
  const { data: policy } = await supabase
    .from('permission_policies').select('*').eq('business_type', v.business_type).single();
  const allowedFields = policy ? policy.allowed_fields : [];

  // build filtered response
  const result = buildResponse(user, profile, v.business_type);

  // audit
  await logAudit(user.id, v, purposeFor(v.business_type), result.decision, allowedFields, result.reason);

  // brute-force check
  const suspicious = await checkBruteForce(v.id);
  if (suspicious) result.warning = 'Unusual verification volume detected — activity logged';

  // legacy log
  await supabase.from('verification_logs').insert({
    user_id: user.id, timestamp: new Date(), result: result.decision,
  });

  res.json(result);
});

/* ═════════════════════════════════════════════════════════
   Admin auth
   ═════════════════════════════════════════════════════════ */
app.post('/admin/login', async (req, res) => {
  const { username, password } = req.body;
  const { data, error } = await supabase
    .from('admin_users').select('*').eq('username', username).single();
  if (error || !data) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, data.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign(
    { id: data.id, username: data.username, role: data.role, type: 'admin' },
    process.env.JWT_SECRET,
    { expiresIn: '8h' },
  );
  res.json({ token, role: data.role, department: data.department });
});

/* ═════════════════════════════════════════════════════════
   Admin — dashboard, search, citizen detail
   ═════════════════════════════════════════════════════════ */
app.get('/admin/dashboard', async (req, res) => {
  const a = decodeAdminJwt(req);
  if (!a) return res.status(401).json({ error: 'Admin auth required' });

  const { count: total } = await supabase.from('audit_trail').select('*', { count: 'exact', head: true });
  const { count: denied } = await supabase.from('audit_trail').select('*', { count: 'exact', head: true }).eq('decision', 'denied');
  const { count: suspicious } = await supabase.from('suspicious_activity').select('*', { count: 'exact', head: true }).eq('resolved', false);
  const { data: byType } = await supabase.from('audit_trail').select('business_type');
  const typeCounts = {};
  (byType || []).forEach(r => { typeCounts[r.business_type] = (typeCounts[r.business_type] || 0) + 1; });

  const { data: recent } = await supabase
    .from('audit_trail')
    .select('*, verifier_organizations(company_name, company_pan)')
    .order('timestamp', { ascending: false }).limit(20);

  const { data: suspiciousEvents } = await supabase
    .from('suspicious_activity')
    .select('*, verifier_organizations(company_name, company_pan)')
    .eq('resolved', false)
    .order('flagged_at', { ascending: false }).limit(10);

  res.json({
    total_verifications: total || 0,
    denied_count: denied || 0,
    unresolved_suspicious: suspicious || 0,
    by_type: typeCounts,
    recent_activity: recent || [],
    suspicious_events: suspiciousEvents || [],
  });
});

app.get('/admin/search', async (req, res) => {
  const a = decodeAdminJwt(req);
  if (!a) return res.status(401).json({ error: 'Admin auth required' });
  const q = (req.query.q || '').trim();
  if (!q) return res.json([]);

  const { data } = await supabase
    .from('users')
    .select('id, name, national_id, dob, photo_url')
    .or(`national_id.ilike.%${q}%,name.ilike.%${q}%`)
    .limit(20);
  res.json(data || []);
});

app.get('/admin/citizen/:id', async (req, res) => {
  const a = decodeAdminJwt(req);
  if (!a) return res.status(401).json({ error: 'Admin auth required' });
  const { data: user } = await supabase.from('users').select('*').eq('id', req.params.id).single();
  if (!user) return res.status(404).json({ error: 'Not found' });
  const { data: profile } = await supabase.from('citizen_profiles').select('*').eq('user_id', user.id).single();
  res.json({ user, profile });
});

app.get('/admin/citizen/:id/knowledge-graph', async (req, res) => {
  const a = decodeAdminJwt(req);
  if (!a) return res.status(401).json({ error: 'Admin auth required' });
  const cid = req.params.id;
  const { data: user } = await supabase.from('users').select('*').eq('id', cid).single();
  if (!user) return res.status(404).json({ error: 'Not found' });
  const { data: profile } = await supabase.from('citizen_profiles').select('*').eq('user_id', cid).single();
  const { count } = await supabase.from('audit_trail').select('*', { count: 'exact', head: true }).eq('citizen_id', cid);
  const { data: last } = await supabase.from('audit_trail').select('timestamp').eq('citizen_id', cid).order('timestamp', { ascending: false }).limit(1);
  const age = computeAge(user.dob);
  const p = profile || {};
  const nodes = [
    { id: 'identity', label: 'Core Identity', data: { name: user.name, national_id: user.national_id, dob: user.dob, age, gender: p.gender || 'N/A', photo_url: user.photo_url } },
    { id: 'kyc', label: 'KYC', data: { status: p.kyc_verified ? 'Verified' : 'Unverified', verified_date: p.kyc_verified_date, risk_level: p.kyc_risk_level || 'pending' } },
    { id: 'address', label: 'Address', data: { province: p.province, district: p.district, municipality: p.municipality, ward: p.ward } },
    { id: 'prescriptions', label: 'Drug Permissions', data: { has_valid_prescription: p.has_valid_prescription || false, expiry: p.prescription_expiry, allowed_drugs: p.allowed_drugs || [], doctor: p.doctor_authorization } },
    { id: 'vehicles', label: 'Vehicles', data: { license: p.license_number || 'None', registration: p.vehicle_registration || 'None' } },
    { id: 'audit', label: 'Access History', data: { total_accesses: count || 0, last_access: last && last[0] ? last[0].timestamp : 'Never' } },
  ];
  const edges = nodes.filter(n => n.id !== 'identity').map(n => ({ from: 'identity', to: n.id }));
  res.json({ nodes, edges });
});

app.get('/admin/citizen/:id/audit-trail', async (req, res) => {
  const a = decodeAdminJwt(req);
  if (!a) return res.status(401).json({ error: 'Admin auth required' });
  const { data } = await supabase
    .from('audit_trail')
    .select('*, verifier_organizations(company_name, company_pan, business_type)')
    .eq('citizen_id', req.params.id)
    .order('timestamp', { ascending: false });
  res.json(data || []);
});

app.get('/admin/verifier/:id/audit-trail', async (req, res) => {
  const a = decodeAdminJwt(req);
  if (!a) return res.status(401).json({ error: 'Admin auth required' });
  const { data } = await supabase
    .from('audit_trail')
    .select('*, users(name, national_id)')
    .eq('verifier_org_id', req.params.id)
    .order('timestamp', { ascending: false });
  res.json(data || []);
});

app.get('/admin/suspicious-activity', async (req, res) => {
  const a = decodeAdminJwt(req);
  if (!a) return res.status(401).json({ error: 'Admin auth required' });
  const { data } = await supabase
    .from('suspicious_activity')
    .select('*, verifier_organizations(company_name, company_pan, business_type)')
    .order('flagged_at', { ascending: false });
  res.json(data || []);
});

app.get('/admin/policies', async (req, res) => {
  const a = decodeAdminJwt(req);
  if (!a) return res.status(401).json({ error: 'Admin auth required' });
  const { data } = await supabase.from('permission_policies').select('*');
  res.json(data || []);
});

app.get('/admin/verifiers', async (req, res) => {
  const a = decodeAdminJwt(req);
  if (!a) return res.status(401).json({ error: 'Admin auth required' });
  const { data } = await supabase.from('verifier_organizations').select('*');
  res.json(data || []);
});

/* ═════════════════════════════════════════════════════════ */
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));