const express = require('express');
const path = require('path');
const app = express();
const port = process.env.PORT || 3000;

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Special MIME type for WASM files
app.use('/ruffle', express.static(path.join(__dirname, 'public', 'ruffle'), {
  setHeaders: (res, path) => {
    if (path.endsWith('.wasm')) {
      res.set('Content-Type', 'application/wasm');
    }
  }
}));
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'pages', 'home.html'));
});

app.get('/games', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'pages', 'games.html'));
});


// Start server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});