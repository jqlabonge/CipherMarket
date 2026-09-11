// Zero-dependency static file server. `npm install` has nothing to fetch
// (see package.json), so this runs instantly even with no network access.
const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 5173;
const ROOT = __dirname;

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.md': 'text/markdown; charset=utf-8',
};

const server = http.createServer((req, res) => {
  let reqPath = decodeURIComponent(req.url.split('?')[0]);
  if (reqPath === '/') reqPath = '/index.html';
  const filePath = path.normalize(path.join(ROOT, reqPath));

  // Also allow serving README.md from the project root for the in-app link.
  const fallback = path.normalize(path.join(ROOT, '..', reqPath));

  const tryServe = (p) => {
    fs.readFile(p, (err, data) => {
      if (err) {
        if (p !== fallback) return tryServe(fallback);
        res.writeHead(404);
        res.end('Not found');
        return;
      }
      const ext = path.extname(p);
      res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
      res.end(data);
    });
  };
  tryServe(filePath);
});

server.listen(PORT, () => {
  console.log(`Black Box Bazaar frontend running at http://localhost:${PORT}`);
});
