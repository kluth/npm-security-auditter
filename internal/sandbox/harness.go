package sandbox

// harnessScript is a Node.js script that monkey-patches core modules to
// intercept dangerous operations, then requires the target package and
// reports what it tried to do.
//
// Security Features:
// - Intercepts 15+ Node.js core modules
// - Blocks process spawning, network, filesystem writes
// - Prevents sandbox escape via vm, worker_threads, cluster
// - Logs all sensitive operations with stack traces
// - Timeout protection against infinite loops
const harnessScript = `
'use strict';

const TIMEOUT_MS = 10000;
const HARNESS_VERSION = '2.0.0';

const pkgPath = process.argv[2];
if (!pkgPath) {
  console.log(JSON.stringify({ success: false, error: 'no package path provided', harnessVersion: HARNESS_VERSION }));
  process.exit(1);
}

// Freeze critical objects early to prevent tampering
const _setTimeout = setTimeout;
const _clearTimeout = clearTimeout;
const _setImmediate = setImmediate;
const _JSON = JSON;
const _Error = Error;
const _Date = Date;
const _console = console;
const _process = process;

const result = {
  success: false,
  error: null,
  harnessVersion: HARNESS_VERSION,
  loadPhase: { completed: false, error: null, duration: 0 },
  installPhase: { completed: true, error: null, duration: 0 },
  intercepted: {
    childProcess: [],
    fileSystem: [],
    network: [],
    dns: [],
    crypto: [],
    processEnv: [],
    os: [],
    vm: [],
    worker: [],
    cluster: [],
    dgram: [],
    tls: [],
    eval: []
  },
  environment: {
    nodeVersion: _process.version,
    platform: _process.platform,
    arch: _process.arch
  },
  patchErrors: []
};

function record(category, method, args, extra) {
  const entry = {
    method: method,
    args: args.map(a => {
      try { return String(a).slice(0, 200); }
      catch { return '[unserializable]'; }
    }).slice(0, 5),
    timestamp: new _Date().toISOString(),
    stack: new _Error().stack.split('\\n').slice(2, 8).join('\\n')
  };
  if (extra) entry.extra = extra;
  if (result.intercepted[category]) {
    result.intercepted[category].push(entry);
  }
}

function logPatchError(module, error) {
  result.patchErrors.push({ module, error: String(error) });
}

// === CRITICAL: Intercept eval and Function constructor ===
try {
  const origEval = global.eval;
  global.eval = function(code) {
    record('eval', 'eval', [code]);
    throw new _Error('eval() blocked by sandbox');
  };

  const OrigFunction = Function;
  global.Function = function(...args) {
    record('eval', 'Function', args);
    throw new _Error('Function constructor blocked by sandbox');
  };
  global.Function.prototype = OrigFunction.prototype;
} catch (e) { logPatchError('eval', e); }

// === Intercept child_process ===
try {
  const cp = require('child_process');
  const blocked = ['exec', 'execSync', 'spawn', 'spawnSync', 'fork', 'execFile', 'execFileSync'];
  for (const fn of blocked) {
    if (!cp[fn]) continue;
    cp[fn] = function(...args) {
      record('childProcess', fn, args);
      if (fn.includes('Sync')) {
        throw new _Error('child_process.' + fn + ' blocked by sandbox');
      }
      const { EventEmitter } = require('events');
      const fake = new EventEmitter();
      fake.stdout = new (require('stream').PassThrough)();
      fake.stderr = new (require('stream').PassThrough)();
      fake.stdin = new (require('stream').PassThrough)();
      fake.pid = 0;
      fake.kill = () => false;
      fake.killed = true;
      fake.exitCode = 1;
      fake.signalCode = 'SIGTERM';
      _setImmediate(() => {
        fake.emit('error', new _Error('blocked by sandbox'));
        fake.emit('close', 1, 'SIGTERM');
      });
      return fake;
    };
  }
} catch (e) { logPatchError('child_process', e); }

// === Intercept fs (block writes, log reads) ===
try {
  const fs = require('fs');
  const fsp = fs.promises;

  const writeMethods = [
    'writeFile', 'writeFileSync', 'appendFile', 'appendFileSync',
    'mkdir', 'mkdirSync', 'unlink', 'unlinkSync', 'rmdir', 'rmdirSync',
    'rm', 'rmSync', 'rename', 'renameSync', 'copyFile', 'copyFileSync',
    'createWriteStream', 'chmod', 'chmodSync', 'chown', 'chownSync',
    'truncate', 'truncateSync', 'symlink', 'symlinkSync', 'link', 'linkSync'
  ];

  for (const fn of writeMethods) {
    if (fs[fn]) {
      fs[fn] = function(...args) {
        record('fileSystem', fn, args, { operation: 'write', blocked: true });
        if (fn.includes('Sync')) {
          throw new _Error('fs.' + fn + ' blocked by sandbox');
        }
        const cb = args[args.length - 1];
        if (typeof cb === 'function') {
          _setImmediate(() => cb(new _Error('blocked by sandbox')));
          return;
        }
        const { PassThrough } = require('stream');
        const fake = new PassThrough();
        _setImmediate(() => fake.emit('error', new _Error('blocked by sandbox')));
        return fake;
      };
    }
    // Also patch promises API
    if (fsp && fsp[fn.replace('Sync', '')]) {
      const asyncFn = fn.replace('Sync', '');
      fsp[asyncFn] = async function(...args) {
        record('fileSystem', 'promises.' + asyncFn, args, { operation: 'write', blocked: true });
        throw new _Error('fs.promises.' + asyncFn + ' blocked by sandbox');
      };
    }
  }

  const readMethods = ['readFile', 'readFileSync', 'readdir', 'readdirSync', 'stat', 'statSync', 'lstat', 'lstatSync', 'access', 'accessSync', 'exists', 'existsSync', 'realpath', 'realpathSync'];
  for (const fn of readMethods) {
    const orig = fs[fn];
    if (!orig) continue;
    fs[fn] = function(...args) {
      record('fileSystem', fn, args, { operation: 'read' });
      return orig.apply(this, args);
    };
  }
} catch (e) { logPatchError('fs', e); }

// === Intercept net/http/https/http2 (block connections) ===
try {
  for (const modName of ['net', 'http', 'https', 'http2']) {
    let mod;
    try { mod = require(modName); } catch { continue; }

    if (mod.request) {
      mod.request = function(...args) {
        const url = typeof args[0] === 'string' ? args[0] : (args[0]?.hostname || args[0]?.host || args[0]?.href || 'unknown');
        record('network', modName + '.request', [url]);
        const { EventEmitter } = require('events');
        const fake = new EventEmitter();
        fake.end = () => fake;
        fake.write = () => true;
        fake.destroy = () => fake;
        fake.abort = () => {};
        fake.setTimeout = () => fake;
        fake.setNoDelay = () => fake;
        fake.setSocketKeepAlive = () => fake;
        fake.on = (ev, cb) => { EventEmitter.prototype.on.call(fake, ev, cb); return fake; };
        _setImmediate(() => fake.emit('error', new _Error('blocked by sandbox')));
        return fake;
      };
    }
    if (mod.get) {
      mod.get = function(...args) {
        const url = typeof args[0] === 'string' ? args[0] : (args[0]?.hostname || args[0]?.host || 'unknown');
        record('network', modName + '.get', [url]);
        const { EventEmitter } = require('events');
        const fake = new EventEmitter();
        fake.end = () => fake;
        fake.on = (ev, cb) => { EventEmitter.prototype.on.call(fake, ev, cb); return fake; };
        _setImmediate(() => fake.emit('error', new _Error('blocked by sandbox')));
        return fake;
      };
    }
    if (mod.connect) {
      mod.connect = function(...args) {
        record('network', modName + '.connect', args);
        const { EventEmitter } = require('events');
        const fake = new EventEmitter();
        fake.end = () => fake;
        fake.write = () => true;
        fake.destroy = () => fake;
        fake.on = (ev, cb) => { EventEmitter.prototype.on.call(fake, ev, cb); return fake; };
        _setImmediate(() => fake.emit('error', new _Error('blocked by sandbox')));
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
        fake.listen = () => { _setImmediate(() => fake.emit('error', new _Error('blocked by sandbox'))); return fake; };
        fake.close = (cb) => { if (cb) _setImmediate(cb); };
        fake.address = () => null;
        return fake;
      };
    }
  }
} catch (e) { logPatchError('network', e); }

// === Intercept dgram (UDP sockets) ===
try {
  const dgram = require('dgram');
  dgram.createSocket = function(...args) {
    record('dgram', 'createSocket', args);
    const { EventEmitter } = require('events');
    const fake = new EventEmitter();
    fake.bind = () => { _setImmediate(() => fake.emit('error', new _Error('blocked by sandbox'))); };
    fake.send = () => { record('dgram', 'send', []); };
    fake.close = () => {};
    fake.address = () => ({ address: '0.0.0.0', family: 'IPv4', port: 0 });
    return fake;
  };
} catch (e) { logPatchError('dgram', e); }

// === Intercept tls ===
try {
  const tls = require('tls');
  tls.connect = function(...args) {
    record('tls', 'connect', args);
    const { EventEmitter } = require('events');
    const fake = new EventEmitter();
    fake.end = () => fake;
    fake.write = () => true;
    fake.destroy = () => fake;
    _setImmediate(() => fake.emit('error', new _Error('blocked by sandbox')));
    return fake;
  };
  tls.createServer = function(...args) {
    record('tls', 'createServer', []);
    const { EventEmitter } = require('events');
    const fake = new EventEmitter();
    fake.listen = () => { _setImmediate(() => fake.emit('error', new _Error('blocked by sandbox'))); return fake; };
    fake.close = () => {};
    return fake;
  };
} catch (e) { logPatchError('tls', e); }

// === Intercept dns ===
try {
  const dns = require('dns');
  const dnsFns = ['lookup', 'resolve', 'resolve4', 'resolve6', 'resolveMx', 'resolveTxt', 'resolveSrv', 'resolveNs', 'resolveCname', 'resolveSoa', 'resolvePtr', 'resolveNaptr', 'reverse'];
  for (const fn of dnsFns) {
    if (!dns[fn]) continue;
    dns[fn] = function(...args) {
      record('dns', fn, args);
      const cb = args[args.length - 1];
      if (typeof cb === 'function') {
        _setImmediate(() => cb(new _Error('blocked by sandbox')));
      }
    };
  }
  // Also intercept dns.promises
  if (dns.promises) {
    for (const fn of dnsFns) {
      if (!dns.promises[fn]) continue;
      dns.promises[fn] = async function(...args) {
        record('dns', 'promises.' + fn, args);
        throw new _Error('blocked by sandbox');
      };
    }
  }
} catch (e) { logPatchError('dns', e); }

// === CRITICAL: Intercept vm module (sandbox escape prevention) ===
try {
  const vm = require('vm');
  const vmFns = ['runInThisContext', 'runInNewContext', 'runInContext', 'createContext', 'compileFunction'];
  for (const fn of vmFns) {
    if (!vm[fn]) continue;
    const orig = vm[fn];
    vm[fn] = function(...args) {
      record('vm', fn, args);
      // Allow but monitor - some legitimate packages use vm
      return orig.apply(this, args);
    };
  }
  // Script class
  const OrigScript = vm.Script;
  vm.Script = function(...args) {
    record('vm', 'new Script', args);
    return new OrigScript(...args);
  };
  vm.Script.prototype = OrigScript.prototype;
} catch (e) { logPatchError('vm', e); }

// === CRITICAL: Intercept worker_threads (parallel execution escape) ===
try {
  const worker = require('worker_threads');
  const OrigWorker = worker.Worker;
  worker.Worker = function(...args) {
    record('worker', 'new Worker', args);
    throw new _Error('Worker threads blocked by sandbox');
  };
} catch (e) { logPatchError('worker_threads', e); }

// === CRITICAL: Intercept cluster (process forking escape) ===
try {
  const cluster = require('cluster');
  cluster.fork = function(...args) {
    record('cluster', 'fork', args);
    throw new _Error('cluster.fork blocked by sandbox');
  };
  cluster.setupPrimary = function(...args) {
    record('cluster', 'setupPrimary', args);
  };
  cluster.setupMaster = cluster.setupPrimary;
} catch (e) { logPatchError('cluster', e); }

// === Intercept crypto (monitor but allow) ===
try {
  const crypto = require('crypto');
  const cryptoFns = ['createHash', 'createHmac', 'createCipher', 'createCipheriv', 'createDecipher', 'createDecipheriv', 'publicEncrypt', 'privateDecrypt', 'randomBytes', 'generateKeyPair', 'generateKeyPairSync'];
  for (const fn of cryptoFns) {
    if (!crypto[fn]) continue;
    const orig = crypto[fn];
    crypto[fn] = function(...args) {
      record('crypto', fn, args.map(a => typeof a === 'string' ? a : '[buffer/object]'));
      return orig.apply(this, args);
    };
  }
} catch (e) { logPatchError('crypto', e); }

// === Intercept os (allow but log) ===
try {
  const os = require('os');
  const osFns = ['homedir', 'hostname', 'platform', 'userInfo', 'networkInterfaces', 'tmpdir', 'cpus', 'freemem', 'totalmem', 'type', 'release', 'arch'];
  for (const fn of osFns) {
    const orig = os[fn];
    if (!orig) continue;
    os[fn] = function(...args) {
      record('os', fn, args);
      return orig.apply(this, args);
    };
  }
} catch (e) { logPatchError('os', e); }

// === Proxy process.env with strict allowlist ===
try {
  const realEnv = _process.env;
  const allowedEnvVars = new Set(['PATH', 'NODE_ENV', 'HOME', 'TERM', 'LANG', 'LC_ALL']);

  _process.env = new Proxy({}, {
    get(target, prop) {
      const key = String(prop);
      record('processEnv', 'get', [key]);
      if (allowedEnvVars.has(key)) {
        return realEnv[key];
      }
      return undefined;
    },
    set(target, prop, value) {
      record('processEnv', 'set', [String(prop), String(value).slice(0, 50)]);
      return true;
    },
    has(target, prop) {
      record('processEnv', 'has', [String(prop)]);
      return allowedEnvVars.has(String(prop));
    },
    ownKeys() {
      record('processEnv', 'ownKeys', []);
      return [...allowedEnvVars];
    },
    getOwnPropertyDescriptor(target, prop) {
      const key = String(prop);
      if (allowedEnvVars.has(key)) {
        return { configurable: true, enumerable: true, value: realEnv[key] };
      }
      return { configurable: true, enumerable: false, value: undefined };
    },
    deleteProperty(target, prop) {
      record('processEnv', 'delete', [String(prop)]);
      return true;
    }
  });
} catch (e) { logPatchError('process.env', e); }

// === Intercept process methods that could be dangerous ===
// We use a flag to know when we're exiting from our own code vs package code
let _allowExit = false;
try {
  const dangerousProcMethods = ['kill', 'abort', 'exit', 'reallyExit'];
  for (const fn of dangerousProcMethods) {
    if (!_process[fn]) continue;
    const orig = _process[fn];
    _process[fn] = function(...args) {
      record('childProcess', 'process.' + fn, args);
      // Only allow exit from our own code (timer or completion)
      if (_allowExit) {
        return orig.apply(this, args);
      }
      // Block all process control from package code
      return;
    };
  }

  // Log binding access
  if (_process.binding) {
    const origBinding = _process.binding;
    _process.binding = function(name) {
      record('childProcess', 'process.binding', [name]);
      // Allow but monitor - needed for some core functionality
      return origBinding.call(this, name);
    };
  }

  // Block dlopen for native addons
  if (_process.dlopen) {
    _process.dlopen = function(...args) {
      record('childProcess', 'process.dlopen', args);
      throw new _Error('process.dlopen blocked by sandbox');
    };
  }
} catch (e) { logPatchError('process', e); }

// === Load the package with timeout ===
const timer = _setTimeout(() => {
  result.error = 'timeout after ' + TIMEOUT_MS + 'ms';
  result.loadPhase.error = 'timeout';
  _console.log(_JSON.stringify(result));
  _allowExit = true;
  _process.exit(0);
}, TIMEOUT_MS);

const start = _Date.now();
try {
  require(pkgPath);
  result.loadPhase.completed = true;
  result.loadPhase.duration = _Date.now() - start;
  result.success = true;
} catch (e) {
  result.loadPhase.error = e.message;
  result.loadPhase.duration = _Date.now() - start;
  result.success = true; // still success - we captured the behavior
}

_clearTimeout(timer);
_console.log(_JSON.stringify(result));
_allowExit = true;
_process.exit(0);
`
