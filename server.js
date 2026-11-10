require('dotenv').config();
const express = require('express'), mongoose = require('mongoose'),
  bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken'), path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const User = mongoose.model('User', new mongoose.Schema({
  userId: { type: String, unique: true, required: true },
  hash: { type: String, required: true },
  name: String, w: Number, ht: Number, a: Number,
  logs: { type: Map, of: Number, default: {} } // { "2026-11-10": glassesDrunk }
}));

const sign = u => jwt.sign({ id: u.userId }, process.env.JWT_SECRET, { expiresIn: '90d' });
const pub = u => ({ name: u.name, w: u.w, ht: u.ht, a: u.a, logs: Object.fromEntries(u.logs) });
const validProfile = (w, ht, a) => w > 10 && w < 300 && ht > 50 && ht < 260 && a > 0 && a < 120;

const auth = (req, res, next) => {
  try {
    req.uid = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), process.env.JWT_SECRET).id;
    next();
  } catch (e) { res.status(401).json({ error: 'Please sign in again.' }); }
};

app.post('/api/register', async (req, res) => {
  try {
    const { id, password, name, w, ht, a } = req.body;
    if (!id || !password || password.length < 4 || !name || !validProfile(w, ht, a))
      return res.status(400).json({ error: 'Please fill in all fields correctly.' });
    const userId = String(id).trim().toLowerCase();
    if (await User.findOne({ userId })) return res.status(409).json({ error: 'This ID already exists. Please sign in.' });
    const u = await User.create({ userId, hash: await bcrypt.hash(password, 10), name, w, ht, a });
    res.json({ token: sign(u), user: pub(u) });
  } catch (e) { res.status(500).json({ error: 'Server error.' }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const u = await User.findOne({ userId: String(req.body.id || '').trim().toLowerCase() });
    if (!u || !(await bcrypt.compare(String(req.body.password || ''), u.hash)))
      return res.status(401).json({ error: 'Wrong ID or password.' });
    res.json({ token: sign(u), user: pub(u) });
  } catch (e) { res.status(500).json({ error: 'Server error.' }); }
});

app.get('/api/me', auth, async (req, res) => {
  const u = await User.findOne({ userId: req.uid });
  u ? res.json({ user: pub(u) }) : res.status(401).json({ error: 'Please sign in again.' });
});

app.put('/api/profile', auth, async (req, res) => {
  const { w, ht, a } = req.body;
  if (!validProfile(w, ht, a)) return res.status(400).json({ error: 'Invalid profile values.' });
  await User.updateOne({ userId: req.uid }, { w, ht, a });
  res.json({ ok: true });
});

app.post('/api/log', auth, async (req, res) => {
  const { date, count } = req.body;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || !Number.isInteger(count) || count < 0 || count > 40)
    return res.status(400).json({ error: 'Invalid log.' });
  await User.updateOne({ userId: req.uid }, { $set: { ['logs.' + date]: count } });
  res.json({ ok: true });
});

mongoose.connect(process.env.MONGODB_URI)
  .then(() => app.listen(process.env.PORT || 3000, () => console.log('Keya running')))
  .catch(e => { console.error('MongoDB connection failed:', e.message); process.exit(1); });
