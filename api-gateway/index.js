const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const prisma = require('../database.js'); // koneksi DB dari root
const { createProxyMiddleware } = require('http-proxy-middleware');
const { decide } = require('./policy'); // Policy Engine

// Nilai bawaan SAMA dengan kode lama agar service tetap cocok.
// Untuk repository, sebaiknya pindahkan ke .env dan jelaskan di README.
const GATEWAY_SECRET = process.env.GATEWAY_SECRET || 'rahasia-gateway-super-aman-123';
const JWT_SECRET = process.env.JWT_SECRET || 'rahasia-gateway-super-aman';
const SERVICE_CLIENT_ID = 'service-nilai';
const SERVICE_CLIENT_SECRET = process.env.SERVICE_CLIENT_SECRET || 'rahasia-nilai-123';

const app = express();
app.use('/auth', express.json());

// Satu titik pencatatan audit: waktu, subjek, endpoint, device, hasil, alasan
const catatAudit = async (req, subjek, hasil, alasan) => {
  try {
    await prisma.auditLog.create({
      data: {
        waktu: new Date(),
        subjek: String(subjek || 'Anonim'),
        endpoint: req.originalUrl,
        device: req.headers['x-device-id'] || 'Tidak ada',
        hasil, // 'allow' atau 'deny'
        alasan
      }
    });
  } catch (err) {
    console.error('Gagal mencatat audit:', err.message);
  }
};

const namaUser = async (id) => {
  try {
    const u = await prisma.user.findUnique({ where: { id: Number(id) } });
    return u ? u.username : String(id);
  } catch {
    return String(id);
  }
};

// ---------- POST /auth/login ----------
app.post('/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    const deviceId = req.headers['x-device-id'];

    if (typeof username !== 'string' || typeof password !== 'string') {
      await catatAudit(req, 'Anonim', 'deny', 'Username atau password tidak diberikan');
      return res.status(401).json({ error: 'Kredensial tidak valid' });
    }
    if (!deviceId) {
      await catatAudit(req, username, 'deny', 'Header X-Device-ID tidak ada');
      return res.status(403).json({ error: 'Header X-Device-ID wajib disertakan' });
    }

    const user = await prisma.user.findUnique({
      where: { username },
      include: { devices: true }
    });

    if (!user) {
      await catatAudit(req, 'Anonim', 'deny', `User tidak ditemukan: ${username}`);
      return res.status(401).json({ error: 'Kredensial tidak valid' });
    }
    if (user.password !== password) { // plaintext hanya untuk praktikum
      await catatAudit(req, user.username, 'deny', 'Password salah');
      return res.status(401).json({ error: 'Kredensial tidak valid' });
    }
    if (!user.devices.find((d) => d.deviceId === deviceId)) {
      await catatAudit(req, user.username, 'deny', `Device tidak terdaftar untuk user ini: ${deviceId}`);
      return res.status(403).json({ error: 'Perangkat tidak terdaftar untuk pengguna ini' });
    }

    // Access token: 10 menit, berisi sub dan role (username tambahan untuk audit)
    const accessToken = jwt.sign(
      { sub: user.id, role: user.role, username: user.username },
      JWT_SECRET,
      { expiresIn: '10m' }
    );

    // Refresh token: 1 hari, disimpan di DB agar dapat dicabut.
    // jti acak mencegah token kembar bila login terjadi dalam detik yang sama.
    const refreshToken = jwt.sign(
      { sub: user.id, jti: crypto.randomUUID() },
      JWT_SECRET,
      { expiresIn: '1d' }
    );
    await prisma.refreshToken.create({ data: { token: refreshToken, userId: user.id } });

    await catatAudit(req, user.username, 'allow', 'Login berhasil dan token diterbitkan');
    res.json({ accessToken, refreshToken });
  } catch (err) {
    console.error('Error /auth/login:', err);
    res.status(500).json({ error: 'Kesalahan server' });
  }
});

// ---------- POST /auth/service ----------
// Body: { clientId, secret }  -> respons: { token }
app.post('/auth/service', async (req, res) => {
  const { clientId, secret } = req.body || {};
  if (clientId === SERVICE_CLIENT_ID && secret === SERVICE_CLIENT_SECRET) {
    const token = jwt.sign({ sub: clientId, role: 'service' }, JWT_SECRET, { expiresIn: '5m' });
    await catatAudit(req, clientId, 'allow', 'Token service diterbitkan');
    return res.json({ token });
  }
  await catatAudit(req, clientId || 'Anonim', 'deny', 'Client ID atau secret tidak valid');
  res.status(401).json({ error: 'Client ID atau Secret tidak valid' });
});

// ---------- POST /auth/logout ----------
app.post('/auth/logout', async (req, res) => {
  const { refreshToken } = req.body || {};
  if (!refreshToken) {
    await catatAudit(req, 'Anonim', 'deny', 'Refresh token tidak diberikan');
    return res.status(401).json({ error: 'Refresh token tidak diberikan' });
  }

  const decoded = jwt.decode(refreshToken);
  const subjek = decoded && decoded.sub ? await namaUser(decoded.sub) : 'Anonim';

  const hasil = await prisma.refreshToken.deleteMany({ where: { token: refreshToken } });
  if (hasil.count === 0) {
    await catatAudit(req, subjek, 'deny', 'Refresh token tidak ditemukan atau sudah dicabut');
    return res.status(401).json({ error: 'Refresh token tidak valid atau sudah dicabut' });
  }

  await catatAudit(req, subjek, 'allow', 'Refresh token dicabut (logout)');
  res.json({ message: 'Refresh token berhasil dicabut' });
});

// ---------- POST /auth/refresh ----------
app.post('/auth/refresh', async (req, res) => {
  const { refreshToken } = req.body || {};
  if (!refreshToken) {
    await catatAudit(req, 'Anonim', 'deny', 'Refresh token tidak diberikan');
    return res.status(401).json({ error: 'Refresh token tidak diberikan' });
  }

  const decodedTanpaVerifikasi = jwt.decode(refreshToken);
  const subjek =
    decodedTanpaVerifikasi && decodedTanpaVerifikasi.sub
      ? await namaUser(decodedTanpaVerifikasi.sub)
      : 'Anonim';

  const tokenDb = await prisma.refreshToken.findFirst({ where: { token: refreshToken } });
  if (!tokenDb) {
    await catatAudit(req, subjek, 'deny', 'Refresh token tidak ada di database atau sudah dicabut');
    return res.status(401).json({ error: 'Refresh token tidak valid atau sudah dicabut' });
  }

  try {
    const decoded = jwt.verify(refreshToken, JWT_SECRET);
    // Role diambil ulang dari database karena refresh token hanya menyimpan ID (sub)
    const user = await prisma.user.findUnique({ where: { id: decoded.sub } });
    if (!user) {
      await catatAudit(req, subjek, 'deny', 'User tidak ditemukan');
      return res.status(401).json({ error: 'User tidak ditemukan' });
    }

    const accessToken = jwt.sign(
      { sub: user.id, role: user.role, username: user.username },
      JWT_SECRET,
      { expiresIn: '10m' }
    );
    await catatAudit(req, user.username, 'allow', 'Access token baru diterbitkan');
    res.json({ accessToken });
  } catch (err) {
    await catatAudit(req, subjek, 'deny', 'Refresh token kedaluwarsa atau palsu');
    res.status(401).json({ error: 'Refresh token kedaluwarsa atau palsu' });
  }
});

// ---------- Middleware PEP: verifikasi token, minta keputusan ke Policy Engine, audit ----------
const pep = async (req, res, next) => {
  const authHeader = req.headers['authorization'] || '';
  const deviceId = req.headers['x-device-id'];
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

  if (!token) {
    await catatAudit(req, 'Anonim', 'deny', 'Token tidak ditemukan');
    return res.status(401).json({ error: 'Akses ditolak oleh Gateway', alasan: 'Token tidak ditemukan' });
  }

  let decoded;
  try {
    decoded = jwt.verify(token, JWT_SECRET); // tanda tangan dan masa berlaku
  } catch (err) {
    await catatAudit(req, 'Anonim', 'deny', 'Token tidak valid atau kedaluwarsa');
    return res.status(401).json({ error: 'Akses ditolak oleh Gateway', alasan: 'Token tidak valid atau kedaluwarsa' });
  }

  const subjek = decoded.username || String(decoded.sub);

  let keputusan;
  try {
    keputusan = await decide({
      method: req.method,
      path: req.baseUrl + req.path, // path penuh, mis. /nilai/1/finalisasi
      query: req.query,
      user: decoded,
      deviceId
    });
  } catch (err) {
    console.error('Error Policy Engine:', err);
    keputusan = { allow: false, status: 403, reason: 'Kesalahan evaluasi kebijakan (ditolak)' };
  }

  await catatAudit(req, subjek, keputusan.allow ? 'allow' : 'deny', keputusan.reason);

  if (!keputusan.allow) {
    return res.status(keputusan.status).json({ error: 'Akses ditolak oleh Gateway', alasan: keputusan.reason });
  }

  req.user = decoded;
  req.headers['x-gateway-secret'] = GATEWAY_SECRET; // agar service mau menerima request ini
  next();
};

// Proxy ke Service Nilai (3001) dan Service Transkrip (3002)
app.use('/nilai', pep, createProxyMiddleware({ target: 'http://localhost:3001', changeOrigin: true }));
app.use('/kelas', pep, createProxyMiddleware({ target: 'http://localhost:3001', changeOrigin: true }));
app.use('/transkrip', pep, createProxyMiddleware({ target: 'http://localhost:3002', changeOrigin: true }));

// Endpoint yang tidak dikenal juga dicatat (default deny)
app.use(async (req, res) => {
  await catatAudit(req, 'Anonim', 'deny', 'Endpoint tidak dikenal');
  res.status(404).json({ error: 'Endpoint tidak ditemukan' });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`API Gateway berjalan di http://localhost:${PORT}`);
});