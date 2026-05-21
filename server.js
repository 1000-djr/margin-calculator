const express = require('express');
const path    = require('path');
const { initDB } = require('./db');
const apiRouter  = require('./api');
const scheduler  = require('./scheduler');

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname)));

app.use('/api', apiRouter);

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

(async () => {
  if (process.env.DATABASE_URL) {
    await initDB();
    scheduler.start();
  } else {
    console.warn('[server] DATABASE_URL 없음 — DB 기능 비활성화');
  }
  app.listen(PORT, () => console.log(`[server] http://localhost:${PORT}`));
})();
