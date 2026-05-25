const { app, ensureDatabaseInitialized } = require('../server');

module.exports = async (req, res) => {
  try {
    await ensureDatabaseInitialized();
    return app(req, res);
  } catch (err) {
    return res.status(500).json({
      error: err.message || 'Gagal inisialisasi database',
    });
  }
};
