const express = require('express');
const { newEnforcer } = require('casbin');
const { PrismaClient } = require('@prisma/client');
const { PrismaAdapter } = require('casbin-prisma-adapter');

const app = express();
const prisma = new PrismaClient();

let enforcer;

// Inisialisasi Casbin Enforcer dengan Prisma Adapter
(async () => {
  try {
    // Buat adapter Prisma, yang akan menggunakan model CasbinRule dari database
    const adapter = await PrismaAdapter.newAdapter();
    // Inisialisasi enforcer dengan file model.conf dan adapter
    enforcer = await newEnforcer('model.conf', adapter);
    // Muat kebijakan dari database
    await enforcer.loadPolicy();
    console.log('Casbin enforcer sudah siap');

    // Tambahkan contoh kebijakan jika belum ada (opsional)
    if (!(await enforcer.hasPolicy("admin", "data", "read"))) {
      await enforcer.addPolicy("admin", "data", "read");
      await enforcer.addPolicy("admin", "data", "write");
      await enforcer.addPolicy("user", "data", "read");
      console.log("Policy berhasil ditambahkan.");
    }
  } catch (error) {
    console.error('Gagal menginisialisasi enforcer:', error);
  }
})();

// Middleware otentikasi: mengambil username dari header dan mencari data user di database
app.use(async (req, res, next) => {
  const username = req.headers['x-user'];
  if (!username) {
    // Jika tidak ada header, anggap sebagai guest dengan role "guest"
    req.user = { username: 'guest', role: 'guest' };
    return next();
  }
  try {
    const user = await prisma.user.findUnique({ where: { username } });
    if (user) {
      req.user = user;
    } else {
      // Jika user tidak ditemukan, set role sebagai guest
      req.user = { username, role: 'guest' };
    }
  } catch (error) {
    req.user = { username, role: 'guest' };
  }
  next();
});

// Middleware otorisasi: menggunakan peran dari data user
function authorize(resource, action) {
  return async (req, res, next) => {
    if (!enforcer || !req.user) {
      return res.status(500).json({ message: 'Enforcer belum siap atau user tidak ditemukan' });
    }
    try {
      // Menggunakan peran user untuk pemeriksaan akses
      const allowed = await enforcer.enforce(req.user.role, resource, action);
      if (allowed) {
        next();
      } else {
        res.status(403).json({ message: 'Akses ditolak' });
      }
    } catch (error) {
      res.status(500).json({ message: 'Terjadi kesalahan saat memeriksa akses', error });
    }
  };
}

// Route untuk membaca data (izin: read pada resource 'data')
app.get('/data', authorize('data', 'read'), (req, res) => {
  res.json({ message: 'Data berhasil dibaca', test: req.user });
});

// Route untuk menulis data (izin: write pada resource 'data')
app.post('/data', authorize('data', 'write'), (req, res) => {
  res.json({ message: 'Data berhasil ditulis', test: req.user });
});

const PORT = 3000;
app.listen(PORT, () => console.log(`Server berjalan pada port ${PORT}`));
