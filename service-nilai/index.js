const express = require('express');
const jwt = require('jsonwebtoken');
const prisma = require('../database.js'); // Mengambil koneksi DB dari root

const app = express();
app.use(express.json());

const GATEWAY_SECRET = 'rahasia-gateway-super-aman-123';
const JWT_SECRET = 'rahasia-gateway-super-aman';

// Middleware Double Verification
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
    return res.status(403).json({ error: 'Token palsu atau kedaluwarsa' });
  }
};

app.use(verifyGateway);

// Endpoint GET /nilai
app.get('/', async (req, res) => {
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
    const kelasIds = kelasDosen.map(k => k.id);
    
    const nilaiKelas = await prisma.nilai.findMany({ 
      where: { kelasId: { in: kelasIds } },
      include: { mahasiswa: { select: { username: true } }, kelas: { select: { namaMatkul: true } } }
    });
    return res.json(nilaiKelas);
  }

  return res.status(403).json({ error: 'Role tidak memiliki izin akses' });
});

// Fungsi pembatasan jam operasional
const cekJamAkses = () => {
  const jam = new Date().getHours();
  return jam >= 7 && jam < 21;
};

// Endpoint PUT /nilai/:id
app.put('/:id', async (req, res) => {
  if (!cekJamAkses()) return res.status(403).json({ error: 'Akses ditolak: Di luar jam kerja (07.00-21.00)' });
  
  const { sub, role } = req.user;
  if (role !== 'dosen') return res.status(403).json({ error: 'Hanya dosen yang bisa mengubah nilai' });

  const nilaiId = Number(req.params.id);
  const { angka } = req.body;

  const nilai = await prisma.nilai.findUnique({ where: { id: nilaiId }, include: { kelas: true } });
  if (!nilai || nilai.kelas.dosenId !== Number(sub)) {
    return res.status(403).json({ error: 'Tidak berhak mengubah nilai kelas ini' });
  }
  if (nilai.isFinal) return res.status(400).json({ error: 'Nilai sudah difinalisasi' });

  const updated = await prisma.nilai.update({ where: { id: nilaiId }, data: { angka } });
  res.json({ message: 'Nilai berhasil diubah', data: updated });
});

// Endpoint POST /kelas/:id/finalisasi
app.post('/:id/finalisasi', async (req, res) => {
  try {
    if (!cekJamAkses()) return res.status(403).json({ error: 'Di luar jam kerja' });
    
    const { sub, role } = req.user;
    if (role !== 'dosen') return res.status(403).json({ error: 'Hanya dosen' });

    const kelasId = Number(req.params.id);
    const kelas = await prisma.kelas.findUnique({ where: { id: kelasId } });
    if (!kelas || kelas.dosenId !== Number(sub)) {
      return res.status(403).json({ error: 'Tidak berhak memfinalisasi' });
    }

    await prisma.nilai.updateMany({ where: { kelasId }, data: { isFinal: true } });

    const authService = await fetch('http://127.0.0.1:3000/auth/service', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ clientId: 'service-nilai', secret: 'rahasia-nilai-123' })
    });
    if (!authService.ok) throw new Error(`Gateway Auth Error: ${authService.status}`);
    const { token: serviceToken } = await authService.json();

    const sync = await fetch('http://127.0.0.1:3000/transkrip/sinkron', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${serviceToken}` },
      body: JSON.stringify({ kelasId })
    });
    if (!sync.ok) throw new Error(`Gateway Sync Error: ${sync.status}`);

    res.json({ message: 'Kelas berhasil difinalisasi dan disinkronisasi' });
  } catch (error) {
    console.error("Crash Finalisasi:", error.message);
    res.status(500).json({ error: 'Terjadi kegagalan sistem', detail: error.message });
  }
});

// Port server
const PORT = 3001;
app.listen(PORT, () => {
  console.log(`Service Nilai berjalan di http://localhost:${PORT}`);
});