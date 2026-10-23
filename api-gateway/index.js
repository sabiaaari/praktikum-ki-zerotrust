const express = require('express');
const jwt = require('jsonwebtoken');
const prisma = require('../database.js'); // Mengambil koneksi DB dari root
const { createProxyMiddleware } = require('http-proxy-middleware'); // Tambahkan di baris atas
const GATEWAY_SECRET = 'rahasia-gateway-super-aman-123';

const app = express();
app.use('/auth', express.json());

const JWT_SECRET = 'rahasia-gateway-super-aman';

// Endpoint Login
app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const deviceId = req.headers['x-device-id'];

  if (!deviceId) return res.status(400).json({ error: 'Header X-Device-ID wajib disertakan' });

  // Cari user beserta device yang terdaftar
  const user = await prisma.user.findUnique({
    where: { username },
    include: { devices: true }
  });

  // Validasi user, password (plaintext untuk praktikum), dan device terdaftar
  if (!user || user.password !== password) {
    return res.status(401).json({ error: 'Kredensial tidak valid' });
  }
  
  const validDevice = user.devices.find(d => d.deviceId === deviceId);
  if (!validDevice) {
    return res.status(403).json({ error: 'Perangkat tidak terdaftar untuk pengguna ini' });
  }

  // Generate Access Token (berlaku 10 menit, berisi sub dan role)
  const accessToken = jwt.sign(
    { sub: user.id, role: user.role },
    JWT_SECRET,
    { expiresIn: '10m' }
  );

  // Generate Refresh Token (berlaku 1 hari)
  const refreshToken = jwt.sign(
    { sub: user.id },
    JWT_SECRET,
    { expiresIn: '1d' }
  );

  // Simpan Refresh Token ke database agar bisa dicabut (revoke)
  await prisma.refreshToken.create({
    data: { token: refreshToken, userId: user.id }
  });

  // Catat Audit Log
  await prisma.auditLog.create({
    data: {
      subjek: user.id.toString(),
      endpoint: '/auth/login',
      device: deviceId,
      hasil: 'allow',
      alasan: 'Login berhasil dan token diterbitkan'
    }
  });

  res.json({ accessToken, refreshToken });
});

// POST /auth/service untuk komunikasi antar-service
app.post('/auth/service', async (req, res) => {
  const { clientId, secret } = req.body;
  // Kredensial statis untuk contoh praktikum
  if (clientId === 'service-nilai' && secret === 'rahasia-nilai-123') {
    const token = jwt.sign({ sub: clientId, role: 'service' }, JWT_SECRET, { expiresIn: '5m' });
    return res.json({ token });
  }
  res.status(401).json({ error: 'Client ID atau Secret tidak valid' });
});

// POST /auth/logout untuk mencabut sesi
app.post('/auth/logout', async (req, res) => {
  const { refreshToken } = req.body;
  await prisma.refreshToken.deleteMany({ where: { token: refreshToken } });
  res.json({ message: 'Refresh token berhasil dicabut' });
});

// Middleware Policy Engine
const policyEngine = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const deviceId = req.headers['x-device-id'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Token tidak ditemukan' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // Berisi sub (ID) dan role

    // Khusus request pengguna (bukan service murni), wajib ada device ID
    if (decoded.role !== 'service' && !deviceId) {
      throw new Error('Device ID tidak ditemukan');
    }

    // Sisipkan secret agar service tujuan mau menerima request ini
    req.headers['x-gateway-secret'] = GATEWAY_SECRET;

    // Catat aktivitas di Audit Log
    await prisma.auditLog.create({
      data: {
        subjek: decoded.sub.toString(),
        endpoint: req.originalUrl,
        device: deviceId || 'service-to-service',
        hasil: 'allow',
        alasan: 'Token valid dan request diteruskan'
      }
    });

    next();
  } catch (err) {
    await prisma.auditLog.create({
      data: {
        subjek: 'unknown',
        endpoint: req.originalUrl,
        device: deviceId || 'unknown',
        hasil: 'deny',
        alasan: err.message || 'Token tidak valid'
      }
    });
    return res.status(403).json({ error: 'Akses ditolak oleh Gateway' });
  }
};

// Pasang Proxy ke Service Nilai (Port 3001) dan Transkrip (Port 3002)
app.use('/nilai', policyEngine, createProxyMiddleware({ target: 'http://localhost:3001', changeOrigin: true }));
app.use('/kelas', policyEngine, createProxyMiddleware({ target: 'http://localhost:3001', changeOrigin: true }));
app.use('/transkrip', policyEngine, createProxyMiddleware({ target: 'http://localhost:3002', changeOrigin: true }));

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`API Gateway berjalan di http://localhost:${PORT}`);
});