const http = require('http');

function buildResponse(query) {
  if (query.length < 12) return null;
  const id = query.slice(0, 2);
  const qdcount = query.readUInt16BE(4);
  if (qdcount !== 1) return null;

  let off = 12;
  while (off < query.length) {
    const len = query[off];
    off += 1;
    if (len === 0) break;
    off += len;
  }
  if (off + 4 > query.length) return null;
  off += 4;
  const question = query.slice(12, off);

  const header = Buffer.alloc(12);
  id.copy(header, 0);
  header.writeUInt16BE(0x8180, 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(1, 6);
  header.writeUInt16BE(0, 8);
  header.writeUInt16BE(0, 10);

  const answer = Buffer.alloc(16);
  answer.writeUInt16BE(0xC00C, 0);
  answer.writeUInt16BE(1, 2);
  answer.writeUInt16BE(1, 4);
  answer.writeUInt32BE(60, 6);
  answer.writeUInt16BE(4, 10);
  answer[12] = 1;
  answer[13] = 2;
  answer[14] = 3;
  answer[15] = 4;

  return Buffer.concat([header, question, answer]);
}

const port = Number(process.env.DOH_MOCK_PORT || 8053);

const server = http.createServer((req, res) => {
  if (req.method !== 'POST') {
    res.statusCode = 405;
    res.end();
    return;
  }
  if (req.url !== '/dns-query') {
    res.statusCode = 404;
    res.end();
    return;
  }
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    const body = Buffer.concat(chunks);
    const resp = buildResponse(body);
    if (!resp) {
      res.statusCode = 400;
      res.end();
      return;
    }
    res.statusCode = 200;
    res.setHeader('content-type', 'application/dns-message');
    res.end(resp);
  });
});

server.listen(port, '127.0.0.1', () => {
  process.stdout.write(`ok: doh-mock listening on http://127.0.0.1:${port}/dns-query\n`);
});

