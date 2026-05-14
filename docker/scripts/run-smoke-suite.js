const crypto = require('crypto');
const fs = require('fs/promises');
const path = require('path');
const { spawn } = require('child_process');

const { queryOnce } = require('./udp-dns-query');

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForHealth(url, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url);
      if (response.ok) {
        return;
      }
    } catch {}
    await sleep(200);
  }
  throw new Error(`health check timeout: ${url}`);
}

async function waitForDns(host, port, name, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let lastError = null;
  while (Date.now() < deadline) {
    try {
      return await queryOnce(host, port, name);
    } catch (error) {
      lastError = error;
      await sleep(250);
    }
  }
  throw new Error(`dns smoke timeout for ${host}:${port} (${lastError ? lastError.message : 'unknown error'})`);
}

function spawnLogged(command, args, options) {
  return spawn(command, args, { stdio: 'inherit', detached: true, ...options });
}

async function run(command, args, options) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: 'inherit', ...options });
    child.on('exit', (code) => {
      if (code === 0) {
        resolve();
        return;
      }
      reject(new Error(`${command} exited with code ${code}`));
    });
  });
}

async function fileExists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function writeWorkerDevVars(filePath, rootSeed, dohMockPort) {
  const content = [
    `ROOT_SEED=${rootSeed}`,
    `DOH_UPSTREAMS='["http://127.0.0.1:${dohMockPort}/dns-query"]'`,
    `CLIENT_REGISTRY=''`,
    '',
  ].join('\n');
  await fs.writeFile(filePath, content, 'utf8');
}

function terminate(child) {
  if (!child || !child.pid) {
    return;
  }
  try {
    process.kill(-child.pid, 'SIGTERM');
  } catch {}
}

async function main() {
  const workspaceRoot = path.resolve(__dirname, '..', '..');
  const workerDir = path.join(workspaceRoot, 'platform', 'cloudflare_worker');
  const dockerDir = path.join(workspaceRoot, 'docker');
  const workerDevVarsPath = path.join(workerDir, '.dev.vars');

  const rootSeed = process.env.ROOT_SEED || process.env.SEED || crypto.randomBytes(32).toString('hex');
  const dnsHost = process.env.DNS_HOST || '127.0.0.1';
  const dnsPort = Number(process.env.DNS_PORT || '1053');
  const dnsName = process.env.DNS_NAME || 'example.com';
  const workerHost = process.env.WORKER_HOST || '127.0.0.1';
  const workerPort = Number(process.env.WORKER_PORT || '8787');
  const dohMockPort = Number(process.env.DOH_MOCK_PORT || '8053');
  const probeMode = process.env.PROBE_MODE || 'none';
  const probeBudgetMs = process.env.PROBE_BUDGET_MS || '50';
  const listenAddr = process.env.LISTEN_ADDR || `${dnsHost}:${dnsPort}`;
  const protocolPath = process.env.PROTOCOL_PATH || '/dns-query';
  const workerBaseUrl = `http://${workerHost}:${workerPort}`;
  const workerUrl = `${workerBaseUrl}${protocolPath}`;
  const healthUrl = `${workerBaseUrl}/health`;

  let originalDevVars = null;
  if (await fileExists(workerDevVarsPath)) {
    originalDevVars = await fs.readFile(workerDevVarsPath, 'utf8');
  }

  let dohMock;
  let worker;
  let dockerNode;

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

  try {
    if (!(await fileExists(path.join(workerDir, 'node_modules', '.bin', 'wrangler')))) {
      await run('pnpm', ['install', '--frozen-lockfile'], { cwd: workerDir, env: devEnv });
    }

    await writeWorkerDevVars(workerDevVarsPath, rootSeed, dohMockPort);

    dohMock = spawnLogged('node', ['scripts/doh-mock-server.js'], {
      cwd: workerDir,
      env: { ...devEnv, DOH_MOCK_PORT: String(dohMockPort) },
    });

    worker = spawnLogged('node_modules/.bin/wrangler', ['dev', '--ip', workerHost, '--port', String(workerPort)], {
      cwd: workerDir,
      env: devEnv,
    });

    await waitForHealth(healthUrl, 20_000);

    dockerNode = spawnLogged('go', ['run', './cmd/trusted-dns'], {
      cwd: dockerDir,
      env: {
        ...process.env,
        WORKER_URL: workerBaseUrl,
        ROOT_SEED: rootSeed,
        LISTEN_ADDR: listenAddr,
        PROBE_MODE: probeMode,
        PROBE_BUDGET_MS: probeBudgetMs,
        PROTOCOL_PATH: protocolPath,
      },
    });

    const result = await waitForDns(dnsHost, dnsPort, dnsName, 20_000);
    console.log(JSON.stringify({
      dnsHost,
      dnsPort,
      dnsName,
      workerUrl,
      probeMode,
      probeBudgetMs,
      rootSeed,
      result,
    }, null, 2));
    console.log('ok');
  } finally {
    terminate(dockerNode);
    terminate(worker);
    terminate(dohMock);
    await sleep(300);

    if (originalDevVars === null) {
      await fs.rm(workerDevVarsPath, { force: true });
    } else {
      await fs.writeFile(workerDevVarsPath, originalDevVars, 'utf8');
    }
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
