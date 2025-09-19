// server.js
const express = require('express');
const bcrypt = require('bcrypt');
const session = require('express-session');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3');

const app = express();
const db = new sqlite3.Database('./users.db');

app.use(express.static('public'));
app.use(bodyParser.json());
app.use(session({
  secret: 'ganti-dengan-secret-random', // pakai env di production
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000*60*60 }
}));

db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password_hash TEXT
)`);

// register (dipakai oleh UI)
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if(!username || !password) return res.status(400).json({ error:'Isi username & password' });
  try {
    const hash = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users(username,password_hash) VALUES(?,?)',[username,hash], function(err){
      if(err) return res.status(400).json({ error:'Username sudah ada' });
      res.json({ ok:true, id:this.lastID });
    });
  } catch(e) { res.status(500).json({ error:'Server error' }); }
});

// login
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err,row) => {
    if(err) return res.status(500).json({ error:'DB error' });
    if(!row) return res.status(401).json({ error:'Username tidak ditemukan' });
    const ok = await bcrypt.compare(password, row.password_hash);
    if(!ok) return res.status(401).json({ error:'Password salah' });
    req.session.userId = row.id;
    req.session.username = row.username;
    res.json({ ok:true });
  });
});

app.get('/dashboard', (req, res) => {
  if(!req.session.userId) return res.status(401).send('Belum login');
  res.send(`<h1>Halo ${req.session.username}</h1><p>Ini dashboard.</p>`);
});

app.post('/logout', (req,res) => {
  req.session.destroy(()=> res.json({ ok:true }));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=> console.log('Server jalan di http://localhost:' + PORT));