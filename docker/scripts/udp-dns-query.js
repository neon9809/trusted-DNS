const dgram = require('dgram');

function buildQuery(name) {
  const id = 0x4242;
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(0x0100, 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(0, 6);
  header.writeUInt16BE(0, 8);
  header.writeUInt16BE(0, 10);

  const labels = name.split('.').filter(Boolean);
  const parts = [];
  for (const l of labels) {
    const b = Buffer.from(l, 'utf8');
    parts.push(Buffer.from([b.length]));
    parts.push(b);
  }
  parts.push(Buffer.from([0]));
  const qtype = Buffer.alloc(2);
  qtype.writeUInt16BE(1, 0);
  const qclass = Buffer.alloc(2);
  qclass.writeUInt16BE(1, 0);
  const question = Buffer.concat([...parts, qtype, qclass]);

  return { id, bytes: Buffer.concat([header, question]) };
}

function parseFirstA(resp) {
  if (resp.length < 12) return null;
  const an = resp.readUInt16BE(6);
  if (an < 1) return null;
  let off = 12;
  while (off < resp.length) {
    const len = resp[off];
    off += 1;
    if (len === 0) break;
    off += len;
  }
  off += 4;
  if (off + 12 > resp.length) return null;
  if ((resp[off] & 0xc0) === 0xc0) off += 2;
  else {
    while (off < resp.length && resp[off] !== 0) off += 1 + resp[off];
    off += 1;
  }
  const type = resp.readUInt16BE(off);
  const rdlen = resp.readUInt16BE(off + 8);
  off += 10;
  if (type !== 1 || rdlen !== 4) return null;
  if (off + 4 > resp.length) return null;
  return `${resp[off]}.${resp[off + 1]}.${resp[off + 2]}.${resp[off + 3]}`;
}

async function queryOnce(host, port, name) {
  const sock = dgram.createSocket('udp4');
  const { id, bytes } = buildQuery(name);

  const resp = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('timeout')), 3000);
    sock.once('message', (msg) => {
      clearTimeout(timer);
      resolve(msg);
    });
    sock.send(bytes, port, host, (err) => {
      if (err) {
        clearTimeout(timer);
        reject(err);
      }
    });
  }).finally(() => sock.close());

  const rid = resp.readUInt16BE(0);
  if (rid !== id) throw new Error(`id mismatch: ${rid} != ${id}`);
  const rcode = resp[3] & 0x0f;
  if (rcode !== 0) throw new Error(`rcode=${rcode}`);

  const ip = parseFirstA(resp);
  return { id, rcode, ip };
}

async function main() {
  const host = process.env.DNS_HOST || '127.0.0.1';
  const port = Number(process.env.DNS_PORT || '1053');
  const name = process.env.DNS_NAME || 'example.com';
  const out = await queryOnce(host, port, name);
  console.log(JSON.stringify({ host, port, name, ...out }, null, 2));
}

module.exports = {
  buildQuery,
  parseFirstA,
  queryOnce,
};

if (require.main === module) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
