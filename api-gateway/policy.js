// api-gateway/policy.js
// Policy Engine (PE): memutuskan allow/deny berdasarkan kebijakan Tabel 3
// dan atribut yang dibaca dari database (device, kelas yang diampu, NIM, status final).
//
// ASUMSI NAMA FIELD (sesuaikan dengan prisma/schema.prisma Anda):
//   Device : userId, deviceId
//   Kelas  : id, dosenId
//   Nilai  : id, kelasId, dan penanda final (final / isFinal / status)
//   User   : id, role, username, (opsional) nim

const fs = require('fs');
const path = require('path');
const prisma = require('../database.js');

const CONFIG_PATH = path.join(__dirname, 'config.json');

// Dibaca setiap kali dicek, sehingga jam akses bisa diubah saat demo
// cukup dengan mengedit config.json (tanpa restart gateway).
function bacaConfig() {
  try {
    return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
  } catch {
    return { accessStart: '07:00', accessEnd: '21:00' };
  }
}

function dalamJamAkses(now = new Date()) {
  const { accessStart, accessEnd } = bacaConfig();
  const [sh, sm] = accessStart.split(':').map(Number);
  const [eh, em] = accessEnd.split(':').map(Number);
  const menit = now.getHours() * 60 + now.getMinutes();
  return menit >= sh * 60 + sm && menit <= eh * 60 + em;
}

const allow = (reason = 'Diizinkan oleh kebijakan') => ({ allow: true, status: 200, reason });
const deny = (status, reason) => ({ allow: false, status, reason });

// Sesuaikan dengan cara Anda menandai nilai yang sudah final
const sudahFinal = (n) =>
  n.final === true || n.isFinal === true || String(n.status || '').toLowerCase() === 'final';

// ctx: { method, path, query, user (isi token), deviceId }
async function decide({ method, path: fullPath, query = {}, user, deviceId }) {
  const p = fullPath.replace(/\/+$/, '') || '/';
  const role = String(user.role || '').toLowerCase();
  const userId = Number(user.sub);
  let m;

  // 1. Token service: least privilege, hanya boleh POST /transkrip/sinkron
  if (role === 'service') {
    return method === 'POST' && p === '/transkrip/sinkron'
      ? allow('Token service untuk sinkron transkrip')
      : deny(403, 'Token service hanya boleh untuk POST /transkrip/sinkron');
  }

  if (!['mahasiswa', 'dosen', 'admin'].includes(role)) {
    return deny(403, `Role tidak dikenal: ${user.role}`);
  }

  // 2. Verifikasi konteks: device harus terdaftar untuk user ini
  if (!deviceId) return deny(403, 'Header X-Device-ID tidak ada');
  const dev = await prisma.device.findFirst({ where: { userId, deviceId } });
  if (!dev) return deny(403, 'Device tidak terdaftar untuk user ini');

  // 3. Kebijakan per endpoint (Tabel 3)

  // GET /nilai : mahasiswa dan dosen
  if (method === 'GET' && p === '/nilai') {
    if (!['mahasiswa', 'dosen'].includes(role)) {
      return deny(403, 'Role admin tidak diizinkan melihat nilai');
    }
    // Jika dosen menyebut kelas tertentu, kelas itu harus diampunya.
    // (Nama parameter kelas_id adalah contoh; sesuaikan dengan API Anda.)
    if (role === 'dosen' && query.kelas_id) {
      const kelas = await prisma.kelas.findUnique({ where: { id: Number(query.kelas_id) } });
      if (!kelas || kelas.dosenId !== userId) return deny(403, 'Bukan dosen pengampu kelas ini');
    }
    return allow();
  }

  // PUT /nilai/:id : dosen pengampu, nilai belum final, dalam jam akses
  if (method === 'PUT' && (m = p.match(/^\/nilai\/(\d+)$/))) {
    if (role !== 'dosen') return deny(403, 'Hanya dosen yang boleh mengubah nilai');
    if (!dalamJamAkses()) return deny(403, 'Di luar jam akses');
    const nilai = await prisma.nilai.findUnique({ where: { id: Number(m[1]) } });
    if (!nilai) return deny(404, 'Nilai tidak ditemukan');
    const kelas = await prisma.kelas.findUnique({ where: { id: nilai.kelasId } });
    if (!kelas || kelas.dosenId !== userId) return deny(403, 'Bukan dosen pengampu kelas ini');
    if (sudahFinal(nilai)) return deny(403, 'Nilai sudah final');
    return allow();
  }

  // POST /nilai/:id/finalisasi atau /kelas/:id/finalisasi (id = id kelas)
  if (method === 'POST' && (m = p.match(/^\/(?:nilai|kelas)\/(\d+)\/finalisasi$/))) {
    if (role !== 'dosen') return deny(403, 'Hanya dosen yang boleh memfinalisasi nilai');
    if (!dalamJamAkses()) return deny(403, 'Di luar jam akses');
    const kelas = await prisma.kelas.findUnique({ where: { id: Number(m[1]) } });
    if (!kelas || kelas.dosenId !== userId) return deny(403, 'Bukan dosen pengampu kelas ini');
    return allow();
  }

  // GET /transkrip/:nim : mahasiswa (NIM sendiri) dan admin (semua)
  if (method === 'GET' && (m = p.match(/^\/transkrip\/([^/]+)$/))) {
    if (role === 'admin') return allow('Admin boleh melihat semua transkrip');
    if (role === 'mahasiswa') {
      const u = await prisma.user.findUnique({ where: { id: userId } });
      const nimSendiri = u && (u.nim || u.username);
      return nimSendiri === m[1] ? allow() : deny(403, 'Bukan NIM milik sendiri');
    }
    return deny(403, 'Role dosen tidak diizinkan melihat transkrip');
  }

  // POST /transkrip/sinkron : hanya token service (token user mana pun ditolak)
  if (method === 'POST' && p === '/transkrip/sinkron') {
    return deny(403, 'Hanya token service yang boleh sinkron transkrip');
  }

  // Default deny
  return deny(403, 'Tidak ada kebijakan untuk endpoint ini');
}

module.exports = { decide, dalamJamAkses };