const express = require('express');
const jwt = require('jsonwebtoken');
const prisma = require('../database.js');

const app = express();
app.use(express.json());

const GATEWAY_SECRET = process.env.GATEWAY_SECRET || 'rahasia-gateway-super-aman-123';
const JWT_SECRET = process.env.JWT_SECRET || 'rahasia-gateway-super-aman';

// Middleware Double Verification (Zero Trust): gateway secret, lalu token
const verifyGateway = (req, res, next) => {
  const secret = req.headers['x-gateway-secret'];
  if (secret !== GATEWAY_SECRET) {
    return res.status(403).json({ error: 'Akses langsung ditolak. Wajib melalui Gateway.' });
  }

  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token tidak diteruskan ke service' });

  try {
    req.user = jwt.verify(token, JWT_SECRET); // tanda tangan dan masa berlaku
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token palsu atau kedaluwarsa' });
  }
};

app.use(verifyGateway);

// Endpoint GET /:nim (diakses via Gateway: /transkrip/:nim)
// Di sistem ini NIM = username mahasiswa.
app.get('/:nim', async (req, res) => {
  try {
    const { sub, role } = req.user;
    const nim = req.params.nim;

    // Role diperiksa dulu, sebelum menyentuh database
    if (role !== 'mahasiswa' && role !== 'admin') {
      return res.status(403).json({ error: 'Role tidak diizinkan mengakses transkrip' });
    }

    let targetUser;
    if (role === 'mahasiswa') {
      // Validasi kepemilikan sebelum mencari data target, agar NIM milik orang lain
      // dan NIM yang tidak ada mendapat jawaban yang sama (tidak membocorkan keberadaan NIM)
      const diri = await prisma.user.findUnique({ where: { id: Number(sub) } });
      if (!diri || diri.username !== nim) {
        return res.status(403).json({ error: 'Hanya bisa melihat transkrip sendiri' });
      }
      targetUser = diri;
    } else {
      targetUser = await prisma.user.findUnique({ where: { username: nim } });
      if (!targetUser) return res.status(404).json({ error: 'Mahasiswa tidak ditemukan' });
    }

    const transkrip = await prisma.transkrip.findUnique({ where: { mahasiswaId: targetUser.id } });
    res.json(transkrip ? { data: JSON.parse(transkrip.dataNilai) } : { message: 'Transkrip masih kosong' });
  } catch (error) {
    console.error('Error GET /transkrip:', error.message);
    res.status(500).json({ error: 'Terjadi kegagalan sistem' });
  }
});

// Endpoint POST /sinkron (diakses via Gateway: /transkrip/sinkron)
// Body: { "kelasId": <id kelas> }
app.post('/sinkron', async (req, res) => {
  try {
    const { role } = req.user;

    if (role !== 'service') {
      return res.status(403).json({ error: 'Hanya token service yang diizinkan untuk sinkronisasi' });
    }

    const kelasId = Number(req.body && req.body.kelasId);
    if (!Number.isInteger(kelasId)) {
      return res.status(400).json({ error: 'kelasId tidak valid' });
    }

    const nilaiFinal = await prisma.nilai.findMany({
      where: { kelasId, isFinal: true },
      include: { kelas: true }
    });

    for (const n of nilaiFinal) {
      const transkrip = await prisma.transkrip.findUnique({ where: { mahasiswaId: n.mahasiswaId } });
      const dataNilai = transkrip ? JSON.parse(transkrip.dataNilai) : [];

      const nilaiBaru = { matkul: n.kelas.namaMatkul, angka: n.angka };
      const index = dataNilai.findIndex((d) => d.matkul === n.kelas.namaMatkul);

      if (index > -1) dataNilai[index] = nilaiBaru;
      else dataNilai.push(nilaiBaru);

      await prisma.transkrip.upsert({
        where: { mahasiswaId: n.mahasiswaId },
        update: { dataNilai: JSON.stringify(dataNilai) },
        create: { mahasiswaId: n.mahasiswaId, dataNilai: JSON.stringify(dataNilai) }
      });
    }

    res.json({ message: 'Sinkronisasi transkrip berhasil diproses', jumlah: nilaiFinal.length });
  } catch (error) {
    console.error('Error POST /transkrip/sinkron:', error.message);
    res.status(500).json({ error: 'Terjadi kegagalan sistem' });
  }
});

const PORT = 3002;
app.listen(PORT, () => {
  console.log(`Service Transkrip berjalan di http://localhost:${PORT}`);
});