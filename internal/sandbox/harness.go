package sandbox

// harnessScript is a Node.js script that monkey-patches core modules to
// intercept dangerous operations, then requires the target package and
// reports what it tried to do.
const harnessScript = `
'use strict';

const TIMEOUT_MS = 10000;
const pkgPath = process.argv[2];
if (!pkgPath) {
  console.log(JSON.stringify({ success: false, error: 'no package path provided' }));
  process.exit(1);
}

const result = {
  success: false,
  error: null,
  loadPhase: { completed: false, error: null, duration: 0 },
  installPhase: { completed: true, error: null, duration: 0 },
  intercepted: {
    childProcess: [],
    fileSystem: [],
    network: [],
    dns: [],
    crypto: [],
    processEnv: [],
    os: []
  },
  environment: {
    nodeVersion: process.version,
    platform: process.platform,
    arch: process.arch
  }
};

function record(category, method, args) {
  const entry = {
    method: method,
    args: args.map(a => String(a)).slice(0, 5),
    timestamp: new Date().toISOString(),
    stack: new Error().stack.split('\n').slice(2, 6).join('\n')
  };
  if (result.intercepted[category]) {
    result.intercepted[category].push(entry);
  }
}

// --- Monkey-patch child_process ---
try {
  const cp = require('child_process');
  const blocked = ['exec', 'execSync', 'spawn', 'spawnSync', 'fork', 'execFile', 'execFileSync'];
  for (const fn of blocked) {
    const orig = cp[fn];
    cp[fn] = function(...args) {
      record('childProcess', fn, args);
      if (fn.includes('Sync')) return Buffer.alloc(0);
      const { EventEmitter } = require('events');
      const fake = new EventEmitter();
      fake.stdout = new (require('stream').PassThrough)();
      fake.stderr = new (require('stream').PassThrough)();
      fake.stdin = new (require('stream').PassThrough)();
      fake.pid = 0;
      fake.kill = () => {};
      setImmediate(() => fake.emit('close', 1));
      return fake;
    };
  }
} catch (e) {}

// --- Monkey-patch fs (block writes, log reads) ---
try {
  const fs = require('fs');
  const writeMethods = [
    'writeFile', 'writeFileSync', 'appendFile', 'appendFileSync',
    'mkdir', 'mkdirSync', 'unlink', 'unlinkSync', 'rmdir', 'rmdirSync',
    'rename', 'renameSync', 'copyFile', 'copyFileSync',
    'createWriteStream'
  ];
  for (const fn of writeMethods) {
    if (!fs[fn]) continue;
    fs[fn] = function(...args) {
      record('fileSystem', fn, args);
      if (fn.includes('Sync')) return undefined;
      const cb = args[args.length - 1];
      if (typeof cb === 'function') setImmediate(() => cb(new Error('blocked by sandbox')));
      const { PassThrough } = require('stream');
      return new PassThrough();
    };
  }
  const readMethods = ['readFile', 'readFileSync', 'readdir', 'readdirSync', 'stat', 'statSync', 'access', 'accessSync', 'exists', 'existsSync'];
  for (const fn of readMethods) {
    const orig = fs[fn];
    if (!orig) continue;
    fs[fn] = function(...args) {
      record('fileSystem', fn, args);
      return orig.apply(this, args);
    };
  }
} catch (e) {}

// --- Monkey-patch net/http/https (block connections) ---
try {
  for (const modName of ['net', 'http', 'https']) {
    const mod = require(modName);
    if (mod.request) {
      const origReq = mod.request;
      mod.request = function(...args) {
        const url = typeof args[0] === 'string' ? args[0] : (args[0].hostname || args[0].host || 'unknown');
        record('network', modName + '.request', [url]);
        const { EventEmitter } = require('events');
        const fake = new EventEmitter();
        fake.end = () => {};
        fake.write = () => {};
        fake.on = (ev, cb) => { EventEmitter.prototype.on.call(fake, ev, cb); return fake; };
        setImmediate(() => fake.emit('error', new Error('blocked by sandbox')));
        return fake;
      };
    }
    if (mod.get) {
      mod.get = function(...args) {
        const url = typeof args[0] === 'string' ? args[0] : (args[0].hostname || args[0].host || 'unknown');
        record('network', modName + '.get', [url]);
        const { EventEmitter } = require('events');
        const fake = new EventEmitter();
        fake.end = () => {};
        setImmediate(() => fake.emit('error', new Error('blocked by sandbox')));
        return fake;
      };
    }
    if (mod.connect) {
      mod.connect = function(...args) {
        record('network', modName + '.connect', args);
        const { EventEmitter } = require('events');
        const fake = new EventEmitter();
        fake.end = () => {};
        fake.write = () => {};
        fake.destroy = () => {};
        setImmediate(() => fake.emit('error', new Error('blocked by sandbox')));
        return fake;
      };
    }
    if (mod.createConnection) {
      mod.createConnection = mod.connect;
    }
    if (mod.createServer) {
      mod.createServer = function(...args) {
        record('network', modName + '.createServer', []);
        const { EventEmitter } = require('events');
        const fake = new EventEmitter();
        fake.listen = () => { setImmediate(() => fake.emit('error', new Error('blocked by sandbox'))); return fake; };
        fake.close = () => {};
        return fake;
      };
    }
  }
} catch (e) {}

// --- Monkey-patch dns ---
try {
  const dns = require('dns');
  for (const fn of ['lookup', 'resolve', 'resolve4', 'resolve6', 'resolveMx', 'resolveTxt']) {
    if (!dns[fn]) continue;
    dns[fn] = function(...args) {
      record('dns', fn, args);
      const cb = args[args.length - 1];
      if (typeof cb === 'function') setImmediate(() => cb(new Error('blocked by sandbox')));
    };
  }
} catch (e) {}

// --- Monkey-patch os (allow but log) ---
try {
  const os = require('os');
  for (const fn of ['homedir', 'hostname', 'platform', 'userInfo', 'networkInterfaces', 'tmpdir']) {
    const orig = os[fn];
    if (!orig) continue;
    os[fn] = function(...args) {
      record('os', fn, args);
      return orig.apply(this, args);
    };
  }
} catch (e) {}

// --- Proxy process.env ---
try {
  const realEnv = process.env;
  process.env = new Proxy({}, {
    get(target, prop) {
      record('processEnv', 'get', [String(prop)]);
      if (prop === 'PATH' || prop === 'NODE_ENV' || prop === 'HOME') {
        return realEnv[prop];
      }
      return undefined;
    },
    set(target, prop, value) {
      record('processEnv', 'set', [String(prop)]);
      return true;
    },
    has(target, prop) {
      record('processEnv', 'has', [String(prop)]);
      return false;
    },
    ownKeys() {
      record('processEnv', 'ownKeys', []);
      return [];
    },
    getOwnPropertyDescriptor(target, prop) {
      return { configurable: true, enumerable: true, value: undefined };
    }
  });
} catch (e) {}

// --- Load the package with timeout ---
const timer = setTimeout(() => {
  result.error = 'timeout after ' + TIMEOUT_MS + 'ms';
  result.loadPhase.error = 'timeout';
  console.log(JSON.stringify(result));
  process.exit(0);
}, TIMEOUT_MS);

const start = Date.now();
try {
  require(pkgPath);
  result.loadPhase.completed = true;
  result.loadPhase.duration = Date.now() - start;
  result.success = true;
} catch (e) {
  result.loadPhase.error = e.message;
  result.loadPhase.duration = Date.now() - start;
  result.success = true; // still success - we captured the behavior
}

clearTimeout(timer);
console.log(JSON.stringify(result));
process.exit(0);
`
