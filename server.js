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

// Root route
app.get('/', (req, res) => {
  res.json({ message: 'NagarikID Backend API', status: 'running' });
});

// Login
app.post('/login', async (req, res) => {
  const { national_id, password } = req.body;
  const { data, error } = await supabase
    .from('users')
    .select('*')
    .eq('national_id', national_id)
    .single();
  if (error || !data) return res.status(401).json({ error: 'Invalid credentials' });
  const isValid = await bcrypt.compare(password, data.password_hash);
  if (!isValid) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ id: data.id, national_id: data.national_id }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

// Generate token
app.get('/generate-token', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token' });
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const uid = decoded.national_id;
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = crypto.randomBytes(4).toString('hex');
    const data = uid + timestamp + nonce;
    const hmac = crypto.createHmac('sha256', process.env.HMAC_SECRET).update(data).digest('hex');
    res.json({ uid, timestamp, nonce, token: hmac });
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// User data
app.get('/user', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token' });
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const { data, error } = await supabase
      .from('users')
      .select('name, national_id, dob, photo_url')
      .eq('id', decoded.id)
      .single();
    if (error) return res.status(404).json({ error: 'User not found' });
    res.json(data);
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Verify
app.post('/verify', async (req, res) => {
  const { uid, timestamp, nonce, token } = req.body;
  const current = Math.floor(Date.now() / 1000);
  if (current - timestamp > 10) return res.json({ verified: false });
  const data = uid + timestamp + nonce;
  const expected = crypto.createHmac('sha256', process.env.HMAC_SECRET).update(data).digest('hex');
  if (token !== expected) return res.json({ verified: false });
  const { data: user, error } = await supabase
    .from('users')
    .select('id, name, dob, national_id, photo_url')
    .eq('national_id', uid)
    .single();
  if (error) return res.json({ verified: false });
  // Log verification
  await supabase.from('verification_logs').insert({
    user_id: user.id,
    timestamp: new Date(),
    result: 'success'
  });
  res.json({ verified: true, name: user.name, dob: user.dob, national_id: user.national_id, photo_url: user.photo_url });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));