const { spawn } = require('child_process');

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function waitForHealth(url, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url);
      if (res.ok) return;
    } catch {}
    await sleep(200);
  }
  throw new Error(`health check timeout: ${url}`);
}

function spawnLogged(cmd, args, options) {
  const p = spawn(cmd, args, { stdio: 'inherit', ...options });
  p.on('exit', (code) => {
    if (code && code !== 0) process.exitCode = code;
  });
  return p;
}

async function run(cmd, args, options) {
  return new Promise((resolve, reject) => {
    const p = spawn(cmd, args, { stdio: 'inherit', ...options });
    p.on('exit', (code) => {
      if (code === 0) resolve();
      else reject(new Error(`${cmd} exited with code ${code}`));
    });
  });
}

async function main() {
  const seedA = process.env.SEED_A;
  const seedB = process.env.SEED_B;
  if (!seedA || !seedB) throw new Error('SEED_A and SEED_B are required');

  const workerUrl = process.env.WORKER_URL || 'http://127.0.0.1:8787/dns-query';
  const healthUrl = process.env.HEALTH_URL || 'http://127.0.0.1:8787/health';

  const dohMock = spawnLogged('node', ['scripts/doh-mock-server.js'], {
    env: { ...process.env, DOH_MOCK_PORT: process.env.DOH_MOCK_PORT || '8053' },
    detached: true,
  });

  const devEnv = {
    ...process.env,
    HTTP_PROXY: '',
    HTTPS_PROXY: '',
    ALL_PROXY: '',
    NO_PROXY: '',
    http_proxy: '',
    https_proxy: '',
    all_proxy: '',
    no_proxy: '',
    NODE_OPTIONS: '',
  };

  const worker = spawnLogged('node_modules/.bin/wrangler', ['dev', '--ip', '127.0.0.1', '--port', '8787'], {
    env: devEnv,
    detached: true,
  });

  try {
    await waitForHealth(healthUrl, 20_000);

    const env = { ...process.env, SEED_A: seedA, SEED_B: seedB, WORKER_URL: workerUrl };
    await run('node', ['scripts/bootstrap-smoke.js'], { env });
    await run('node', ['scripts/query-smoke.js'], { env });
    await run('node', ['scripts/refresh-smoke.js'], { env });
  } finally {
    try {
      if (worker.pid) process.kill(-worker.pid, 'SIGTERM');
    } catch {}
    try {
      if (dohMock.pid) process.kill(-dohMock.pid, 'SIGTERM');
    } catch {}
    await sleep(300);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
