const express = require('express');
const jwt = require('jsonwebtoken');
const prisma = require('../database.js');

const app = express();
app.use(express.json());

const GATEWAY_SECRET = 'rahasia-gateway-super-aman-123';
const JWT_SECRET = 'rahasia-gateway-super-aman';

// Middleware Double Verification (Zero Trust)
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

// Endpoint GET /:nim (diakses via Gateway: /transkrip/:nim)
app.get('/:nim', async (req, res) => {
  const { sub, role } = req.user;
  const nim = req.params.nim;

  const targetUser = await prisma.user.findUnique({ where: { username: nim } });
  if (!targetUser) return res.status(404).json({ error: 'Mahasiswa tidak ditemukan' });

  // Validasi Kepemilikan Data
  if (role === 'mahasiswa' && targetUser.id !== Number(sub)) {
    return res.status(403).json({ error: 'Hanya bisa melihat transkrip sendiri' });
  }
  if (role !== 'mahasiswa' && role !== 'admin') {
    return res.status(403).json({ error: 'Role tidak diizinkan mengakses transkrip' });
  }

  const transkrip = await prisma.transkrip.findUnique({ where: { mahasiswaId: targetUser.id } });
  res.json(transkrip ? { data: JSON.parse(transkrip.dataNilai) } : { message: 'Transkrip masih kosong' });
});

// Endpoint POST /sinkron (diakses via Gateway: /transkrip/sinkron)
app.post('/sinkron', async (req, res) => {
  const { role } = req.user;
  
  if (role !== 'service') {
    return res.status(403).json({ error: 'Hanya token service yang diizinkan untuk sinkronisasi' });
  }

  const { kelasId } = req.body;
  const nilaiFinal = await prisma.nilai.findMany({
    where: { kelasId: Number(kelasId), isFinal: true },
    include: { kelas: true }
  });

  for (const n of nilaiFinal) {
    let transkrip = await prisma.transkrip.findUnique({ where: { mahasiswaId: n.mahasiswaId } });
    let dataNilai = transkrip ? JSON.parse(transkrip.dataNilai) : [];

    const nilaiBaru = { matkul: n.kelas.namaMatkul, angka: n.angka };
    const index = dataNilai.findIndex(d => d.matkul === n.kelas.namaMatkul);
    
    if (index > -1) dataNilai[index] = nilaiBaru;
    else dataNilai.push(nilaiBaru);

    await prisma.transkrip.upsert({
      where: { mahasiswaId: n.mahasiswaId },
      update: { dataNilai: JSON.stringify(dataNilai) },
      create: { mahasiswaId: n.mahasiswaId, dataNilai: JSON.stringify(dataNilai) }
    });
  }

  res.json({ message: 'Sinkronisasi transkrip berhasil diproses' });
});

const PORT = 3002;
app.listen(PORT, () => {
  console.log(`Service Transkrip berjalan di http://localhost:${PORT}`);
});