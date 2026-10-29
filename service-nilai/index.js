const express = require('express');
const jwt = require('jsonwebtoken');
const prisma = require('../database.js'); // Mengambil koneksi DB dari root

const app = express();
app.use(express.json());

const GATEWAY_SECRET = process.env.GATEWAY_SECRET || 'rahasia-gateway-super-aman-123';
const JWT_SECRET = process.env.JWT_SECRET || 'rahasia-gateway-super-aman';
const SERVICE_CLIENT_ID = 'service-nilai';
const SERVICE_CLIENT_SECRET = process.env.SERVICE_CLIENT_SECRET || 'rahasia-nilai-123';
const GATEWAY_URL = process.env.GATEWAY_URL || 'http://127.0.0.1:3000';

// Middleware Double Verification: gateway secret, lalu tanda tangan dan masa berlaku token
const verifyGateway = (req, res, next) => {
  const secret = req.headers['x-gateway-secret'];
  if (secret !== GATEWAY_SECRET) {
    return res.status(403).json({ error: 'Akses langsung ditolak. Wajib melalui Gateway.' });
  }

  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token tidak diteruskan ke service' });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token palsu atau kedaluwarsa' });
  }
};

app.use(verifyGateway);

// Endpoint GET /nilai
app.get('/', async (req, res) => {
  try {
    const { sub, role } = req.user;

    if (role === 'mahasiswa') {
      const nilaiMhs = await prisma.nilai.findMany({
        where: { mahasiswaId: Number(sub) },
        include: { kelas: { select: { namaMatkul: true } } }
      });
      return res.json(nilaiMhs);
    }

    if (role === 'dosen') {
      const kelasDosen = await prisma.kelas.findMany({
        where: { dosenId: Number(sub) },
        select: { id: true }
      });
      const kelasIds = kelasDosen.map((k) => k.id);

      const nilaiKelas = await prisma.nilai.findMany({
        where: { kelasId: { in: kelasIds } },
        include: { mahasiswa: { select: { username: true } }, kelas: { select: { namaMatkul: true } } }
      });
      return res.json(nilaiKelas);
    }

    return res.status(403).json({ error: 'Role tidak memiliki izin akses' });
  } catch (error) {
    console.error('Error GET /nilai:', error.message);
    res.status(500).json({ error: 'Terjadi kegagalan sistem' });
  }
});

// Endpoint PUT /nilai/:id
// Jam akses TIDAK dicek di sini. Keputusan jam akses ada di Policy Engine gateway
// (config.json), supaya satu sumber kebenaran dan tercatat di audit log.
app.put('/:id', async (req, res) => {
  try {
    const { sub, role } = req.user;
    if (role !== 'dosen') return res.status(403).json({ error: 'Hanya dosen yang dapat mengubah nilai' });

    const nilaiId = Number(req.params.id);
    const { angka } = req.body || {};
    if (!Number.isInteger(nilaiId) || angka === undefined || Number.isNaN(Number(angka))) {
      return res.status(400).json({ error: 'id atau angka tidak valid' });
    }

    const nilaiData = await prisma.nilai.findUnique({
      where: { id: nilaiId },
      include: { kelas: true }
    });

    if (!nilaiData) return res.status(404).json({ error: 'Data nilai tidak ditemukan' });
    if (nilaiData.kelas.dosenId !== Number(sub)) return res.status(403).json({ error: 'Tidak berhak mengubah nilai di kelas ini' });
    if (nilaiData.isFinal) return res.status(403).json({ error: 'Nilai sudah difinalisasi dan tidak dapat diubah' });

    const updateNilai = await prisma.nilai.update({
      where: { id: nilaiId },
      data: { angka: Number(angka) }
    });

    res.json({ message: 'Nilai berhasil diperbarui', data: updateNilai });
  } catch (error) {
    console.error('Error PUT /nilai:', error.message);
    res.status(500).json({ error: 'Terjadi kegagalan sistem' });
  }
});

// Endpoint POST /kelas/:id/finalisasi (juga terjangkau lewat /nilai/:id/finalisasi)
app.post('/:id/finalisasi', async (req, res) => {
  try {
    const { sub, role } = req.user;
    if (role !== 'dosen') return res.status(403).json({ error: 'Hanya dosen' });

    const kelasId = Number(req.params.id);
    if (!Number.isInteger(kelasId)) return res.status(400).json({ error: 'id kelas tidak valid' });

    const kelas = await prisma.kelas.findUnique({ where: { id: kelasId } });
    if (!kelas || kelas.dosenId !== Number(sub)) {
      return res.status(403).json({ error: 'Tidak berhak memfinalisasi' });
    }

    // 1. Ubah status menjadi final
    await prisma.nilai.updateMany({ where: { kelasId }, data: { isFinal: true } });

    // 2. Ambil token service dari Gateway
    const authService = await fetch(`${GATEWAY_URL}/auth/service`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ clientId: SERVICE_CLIENT_ID, secret: SERVICE_CLIENT_SECRET })
    });
    if (!authService.ok) throw new Error(`Gateway Auth Error: ${authService.status}`);
    const { token: serviceToken } = await authService.json();

    // 3. Satu panggilan sinkron untuk seluruh kelas, lewat Gateway (bukan langsung ke port 3002).
    //    Service Transkrip membaca sendiri semua nilai final milik kelas ini.
    const sync = await fetch(`${GATEWAY_URL}/transkrip/sinkron`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${serviceToken}` },
      body: JSON.stringify({ kelasId })
    });
    if (!sync.ok) throw new Error(`Gateway Sync Error: ${sync.status}`);

    res.json({ message: 'Kelas berhasil difinalisasi dan disinkronisasi' });
  } catch (error) {
    console.error('Crash Finalisasi:', error.message);
    res.status(500).json({ error: 'Terjadi kegagalan sistem', detail: error.message });
  }
});

// Port server
const PORT = 3001;
app.listen(PORT, () => {
  console.log(`Service Nilai berjalan di http://localhost:${PORT}`);
});