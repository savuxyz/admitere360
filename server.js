import http from 'node:http';
import { readFileSync } from 'node:fs';

const INDEX = readFileSync(new URL('./public/index.html', import.meta.url));
const port = Number(process.env.PORT ?? 3000);

http.createServer((req, res) => {
  // deocamdata avem doar pagina de start
  if (req.method === 'GET' && req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(INDEX);
  }
  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('Pagina nu exista.');
}).listen(port, '127.0.0.1', () => console.log(`Admitere360 pornit: http://localhost:${port}`));
