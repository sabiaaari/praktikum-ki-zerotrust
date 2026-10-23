const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function main() {
  // Hapus data lama dengan urutan dari child ke parent
  await prisma.auditLog.deleteMany();
  await prisma.transkrip.deleteMany();
  await prisma.nilai.deleteMany();
  await prisma.kelas.deleteMany();
  await prisma.device.deleteMany();
  await prisma.user.deleteMany();

  // 1. Buat User & Device
  await prisma.user.create({ data: { username: 'admin1', password: 'password123', role: 'admin', devices: { create: { deviceId: 'dev-admin-1' } } } });
  const dosen1 = await prisma.user.create({ data: { username: 'dosen1', password: 'password123', role: 'dosen', devices: { create: { deviceId: 'dev-dosen-1' } } } });
  const dosen2 = await prisma.user.create({ data: { username: 'dosen2', password: 'password123', role: 'dosen', devices: { create: { deviceId: 'dev-dosen-2' } } } });
  const mhs1 = await prisma.user.create({ data: { username: 'mhs1', password: 'password123', role: 'mahasiswa', devices: { create: { deviceId: 'dev-mhs-1' } } } });
  const mhs2 = await prisma.user.create({ data: { username: 'mhs2', password: 'password123', role: 'mahasiswa', devices: { create: { deviceId: 'dev-mhs-2' } } } });

  // 2. Buat Kelas
  const kelas1 = await prisma.kelas.create({ data: { namaMatkul: 'Keamanan Informasi', dosenId: dosen1.id } });
  await prisma.kelas.create({ data: { namaMatkul: 'Pemrograman Web', dosenId: dosen2.id } });

  // 3. Masukkan Data Nilai Mentah (Belum Final)
  await prisma.nilai.create({ data: { angka: 85, mahasiswaId: mhs1.id, kelasId: kelas1.id, isFinal: false } });
  await prisma.nilai.create({ data: { angka: 90, mahasiswaId: mhs2.id, kelasId: kelas1.id, isFinal: false } });

  console.log("Seeding selesai dengan penambahan data Nilai.");
}

main().catch(console.error).finally(() => prisma.$disconnect());