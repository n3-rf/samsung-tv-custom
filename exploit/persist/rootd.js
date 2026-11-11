'use strict';
// SPDX-License-Identifier: AGPL-3.0-only
//
// Kant-M2 persistent root daemon.
//
// This file is installed in /opt/kant-root/rootd.js by install.sh and started
// at boot by /opt/kant-root/boot.sh (the AT-HUB.service -> parseinfo.sh hook).
// It deliberately uses only already-signed firmware executables: /usr/bin/node
// runs the daemon, /bin/bash runs commands. No unsigned binary is executed, so
// the Samsung UEP gate does not need to be patched for persistence.
//
// Node 4.4.3 compatible: no async/await, no let/const, no arrow functions and
// no Buffer.from-only API. The protocol is:
//
//   server:  KANT-ROOT/1 <nonce hex>\n
//   client:  AUTH <hex HMAC-SHA256(token, nonce)>\n
//   server:  OK <version>\n        (or DENY\n / BUSY\n)
//
//   client:  PING\n
//   server:  PONG\n
//
//   client:  EXEC <seq> <timeout_ms> <base64 command>\n
//   server:  RESULT <seq> <exit> <timedout> <base64 stdout> <base64 stderr>\n
//
//   client:  SHELL\n               -> raw /bin/bash -i over the socket
//   client:  QUIT\n
//
// The token is a 64-hex-character secret stored in /opt/kant-root/token, mode
// 0600. It is never sent over the wire. The connection is not encrypted:
// use it only on a trusted LAN, or tunnel it over SSH/VPN.
var fs = require('fs');
var net = require('net');
var crypto = require('crypto');
var childProcess = require('child_process');

var VERSION = '1.0.0';
var ROOT = process.env.KANT_ROOT_DIR || '/opt/kant-root';
var TOKEN_FILE = process.env.KANT_ROOT_TOKEN_FILE || (ROOT + '/token');
var LOG_FILE = process.env.KANT_ROOT_LOG || (ROOT + '/rootd.log');
var BIND = process.env.KANT_ROOT_BIND || '0.0.0.0';
var PORT = parseInt(process.env.KANT_ROOT_PORT || '5555', 10);
var LABEL = process.env.KANT_ROOT_LABEL || '';
var PORT_FILE = process.env.KANT_ROOT_PORT_FILE || '';
var LOCK_FILE = process.env.KANT_ROOT_LOCK || '/tmp/kant-rootd.lock';
var PID_FILE = process.env.KANT_ROOT_PID || '/tmp/kant-rootd.pid';
var MAX_SESSIONS = parseInt(process.env.KANT_ROOT_MAX_SESSIONS || '4', 10);

var AUTH_TIMEOUT_MS = 10000;
var MAX_FRAME_BYTES = 1024 * 1024;
var MAX_OUTPUT_BYTES = 4 * 1024 * 1024;
var LOG_LIMIT = 512 * 1024;
var LABEL_RE = /^[A-Za-z0-9_:.\/-]{1,128}$/;

var token = null;
var activeSessions = 0;
var nextSessionId = 0;

// Node 4.4 inherits Buffer.from from TypedArray; it rejects strings.
function fromString(value, encoding) {
    if (typeof Buffer.from === 'function') {
        try {
            var probe = Buffer.from('a');
            if (probe && probe.length === 1 && probe.toString() === 'a') {
                return Buffer.from(value, encoding);
            }
        } catch (e) { }
    }
    return new Buffer(value, encoding);
}

function toBase64(value) {
    if (value === null || value === undefined) return '';
    if (Buffer.isBuffer(value)) return value.toString('base64');
    return fromString(String(value), 'utf8').toString('base64');
}

function shellQuote(value) {
    return "'" + String(value).replace(/'/g, "'\\''") + "'";
}

function errorText(error) {
    if (!error) return '';
    return String(error.stack || error.message || error);
}

function log(message) {
    var line = new Date().toISOString() + ' ' + message + '\n';
    try {
        var stat = fs.statSync(LOG_FILE);
        if (stat.size > LOG_LIMIT) fs.writeFileSync(LOG_FILE, '');
    } catch (e) { }
    try { fs.appendFileSync(LOG_FILE, line, { mode: 384 }); } catch (e) { }
}

function identity() {
    var status = '';
    try { status = fs.readFileSync('/proc/self/status', 'utf8'); } catch (e) { }
    var cap = /^CapEff:\s*([0-9a-fA-F]+)/m.exec(status);
    var smack = '';
    try { smack = fs.readFileSync('/proc/self/attr/current', 'utf8').trim(); } catch (e) { }
    return {
        pid: process.pid,
        uid: typeof process.getuid === 'function' ? process.getuid() : -1,
        euid: typeof process.geteuid === 'function' ? process.geteuid() : -1,
        gid: typeof process.getgid === 'function' ? process.getgid() : -1,
        cap_eff: cap ? cap[1] : 'unknown',
        smack: smack
    };
}

function isAlive(pid) {
    try { process.kill(pid, 0); return true; } catch (e) { return e.code === 'EPERM'; }
}

// A stale lock can name a PID that the kernel has reused for another process.
// On the TV /proc/<pid>/cmdline lets us avoid refusing to start in that case.
function lockOwnerAlive(pid) {
    if (!isAlive(pid)) return false;
    try {
        var cmdline = fs.readFileSync('/proc/' + pid + '/cmdline', 'utf8');
        if (cmdline) return cmdline.indexOf('rootd.js') !== -1;
    } catch (e) { }
    return true;
}

function acquireLock() {
    try {
        fs.writeFileSync(LOCK_FILE, String(process.pid), { mode: 384, flag: 'wx' });
        return true;
    } catch (e) {
        if (e.code !== 'EEXIST') { log('lock error: ' + errorText(e)); return true; }
    }
    var old = 0;
    try { old = parseInt(fs.readFileSync(LOCK_FILE, 'utf8'), 10); } catch (e) { }
    if (old && old !== process.pid && lockOwnerAlive(old)) return false;
    try { fs.unlinkSync(LOCK_FILE); } catch (e) { }
    try {
        fs.writeFileSync(LOCK_FILE, String(process.pid), { mode: 384, flag: 'wx' });
        return true;
    } catch (e) {
        log('lock recreate error: ' + errorText(e));
        return true;
    }
}

function releaseLock() {
    try {
        var old = parseInt(fs.readFileSync(LOCK_FILE, 'utf8'), 10);
        if (old === process.pid) fs.unlinkSync(LOCK_FILE);
    } catch (e) { }
    try {
        var pid = parseInt(fs.readFileSync(PID_FILE, 'utf8'), 10);
        if (pid === process.pid) fs.unlinkSync(PID_FILE);
    } catch (e) { }
}

function loadToken() {
    if (fs.existsSync(TOKEN_FILE)) {
        var value = '';
        try { value = fs.readFileSync(TOKEN_FILE, 'utf8').replace(/\s+/g, ''); }
        catch (e) { log('cannot read token file: ' + errorText(e)); process.exit(1); }
        if (!/^[0-9a-fA-F]{64}$/.test(value)) {
            log('token file is not 64 hex characters; refusing to start');
            process.exit(1);
        }
        try { fs.chmodSync(TOKEN_FILE, 384); } catch (e) { }
        return fromString(value.toLowerCase(), 'hex');
    }
    var generated = crypto.randomBytes(32).toString('hex');
    try { fs.writeFileSync(TOKEN_FILE, generated + '\n', { mode: 384 }); }
    catch (e) { log('cannot create token file: ' + errorText(e)); process.exit(1); }
    log('generated a new token file');
    try { process.stdout.write('KANT-ROOT-TOKEN ' + generated + '\n'); } catch (e) { }
    return fromString(generated, 'hex');
}

function hmac(nonce) {
    return crypto.createHmac('sha256', token).update(nonce).digest('hex');
}

function constantTimeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
    var difference = 0;
    for (var i = 0; i < a.length; i++) difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return difference === 0;
}

function shellEnv() {
    return {
        PATH: '/usr/sbin:/usr/bin:/sbin:/bin',
        HOME: '/root',
        USER: 'root',
        LOGNAME: 'root',
        TERM: 'dumb',
        LANG: 'C'
    };
}

// Write the requested SMACK label in the child before running the command.
// The wrapper is only used when an operator explicitly configures a label.
function wrapCommand(command) {
    if (!LABEL || !LABEL_RE.test(LABEL)) return command;
    return 'printf %s ' + shellQuote(LABEL) + ' > /proc/self/attr/current 2>/dev/null; ' +
        '(printf %s ' + shellQuote(toBase64(command)) + ' | /usr/bin/base64 -d | /bin/sh)';
}

function send(session, text) {
    return socketWrite(session, text);
}

function socketWrite(session, data) {
    try {
        if (session.socket && !session.socket.destroyed && session.socket.writable) {
            session.socket.write(data);
            return true;
        }
    } catch (e) {
        log('write error: ' + errorText(e));
    }
    return false;
}

function execute(session, seq, timeoutMs, command) {
    var started = Date.now();
    var finished = false;
    try {
        childProcess.exec(wrapCommand(command), {
            timeout: timeoutMs,
            killSignal: 'SIGKILL',
            maxBuffer: MAX_OUTPUT_BYTES,
            encoding: 'buffer',
            env: shellEnv(),
            cwd: '/'
        }, function (error, stdout, stderr) {
            if (finished) return;
            finished = true;
            var exitCode = 0;
            var timedOut = 0;
            if (error) {
                exitCode = typeof error.code === 'number' ? error.code : 1;
                timedOut = error.killed || (Date.now() - started) >= (timeoutMs - 100) ? 1 : 0;
                if (!stdout && !stderr) stderr = fromString(String(error.message || error), 'utf8');
            }
            send(session, 'RESULT\t' + seq + '\t' + exitCode + '\t' + timedOut + '\t' +
                toBase64(stdout) + '\t' + toBase64(stderr) + '\n');
            log('exec seq=' + seq + ' exit=' + exitCode + ' timedout=' + timedOut +
                ' stdout=' + (stdout ? stdout.length : 0) + ' stderr=' + (stderr ? stderr.length : 0));
        });
    } catch (e) {
        send(session, 'RESULT\t' + seq + '\t1\t0\t\t' + toBase64(errorText(e)) + '\n');
        log('exec throw: ' + errorText(e));
    }
}

function startShell(session) {
    var env = shellEnv();
    env.PS1 = 'kant# ';
    env.TERM = 'xterm';
    var args;
    if (LABEL && LABEL_RE.test(LABEL)) {
        args = ['-c', 'printf %s ' + shellQuote(LABEL) +
            ' > /proc/self/attr/current 2>/dev/null; exec /bin/bash -i'];
    } else {
        args = ['-i'];
    }
    var child = childProcess.spawn('/bin/bash', args, { env: env, cwd: '/' });
    session.phase = 'shell';
    session.shell = child;
    log('shell started seq=' + session.id);
    child.stdout.on('data', function (chunk) {
        socketWrite(session, chunk);
    });
    child.stderr.on('data', function (chunk) {
        socketWrite(session, chunk);
    });
    child.stdin.on('error', function (e) {
        log('shell stdin error: ' + errorText(e));
    });
    // Bytes that arrived in the same packet as the trailing newline of
    // "SHELL\n" are still in session.buffer; forward them to the shell.
    if (session.buffer.length) {
        try { child.stdin.write(session.buffer); } catch (e) { }
        session.buffer = '';
    }
    // Use 'close' (all stdio flushed) rather than 'exit' so the final output
    // of the command is never dropped, which matters on Node 4.4.3.
    child.on('close', function (code, signal) {
        session.shell = null;
        log('shell exit code=' + code + ' signal=' + signal);
        socketWrite(session, '\n[kant-root shell exited]\n');
        try { session.socket.end(); } catch (e) { }
    });
    child.on('error', function (e) {
        session.shell = null;
        log('shell error: ' + errorText(e));
        try { session.socket.destroy(); } catch (e2) { }
    });
    session.socket.on('end', function () {
        // Half-close from the client means "no more input": let bash finish.
        try { child.stdin.end(); } catch (e) { }
    });
    session.socket.on('close', function () {
        try { child.kill('SIGHUP'); } catch (e) { }
    });
}

function handleFrame(session, line) {
    if (line === 'PING') {
        send(session, 'PONG\n');
        return;
    }
    if (line === 'SHELL') {
        startShell(session);
        return;
    }
    if (line === 'QUIT') {
        send(session, 'BYE\n');
        session.socket.end();
        return;
    }
    var fields = line.split('\t');
    if (fields[0] !== 'EXEC' || fields.length !== 4) {
        send(session, 'ERR unknown frame\n');
        log('unknown frame from ' + session.remote);
        return;
    }
    var seq = fields[1];
    var timeoutMs = Number(fields[2]);
    if (!/^[1-9][0-9]{0,15}$/.test(seq) || !isFinite(timeoutMs) ||
        Math.floor(timeoutMs) !== timeoutMs || timeoutMs < 1 || timeoutMs > 120000) {
        send(session, 'ERR invalid exec\n');
        log('invalid EXEC frame from ' + session.remote);
        return;
    }
    var command = fromString(fields[3], 'base64').toString('utf8');
    if (!command || command.length > 65536) {
        send(session, 'ERR empty or oversized command\n');
        log('empty or oversized command from ' + session.remote);
        return;
    }
    execute(session, seq, timeoutMs, command);
}

function handleData(session, chunk) {
    if (session.phase === 'shell') {
        if (session.shell) {
            try { session.shell.stdin.write(chunk); } catch (e) { }
        }
        return;
    }
    session.buffer += chunk.toString('utf8');
    if (session.buffer.length > MAX_FRAME_BYTES) {
        log('oversized frame from ' + session.remote);
        session.socket.destroy();
        return;
    }
    var index;
    while ((index = session.buffer.indexOf('\n')) !== -1) {
        var line = session.buffer.slice(0, index);
        session.buffer = session.buffer.slice(index + 1);
        if (!line) continue;
        if (session.phase === 'greeting') {
            var match = /^AUTH ([0-9a-fA-F]{64})$/.exec(line);
            if (!match || !constantTimeEqual(hmac(session.nonce), match[1].toLowerCase())) {
                log('auth failure from ' + session.remote);
                send(session, 'DENY\n');
                session.socket.destroy();
                return;
            }
            if (session.timer) { clearTimeout(session.timer); session.timer = null; }
            session.phase = 'ready';
            log('auth ok from ' + session.remote);
            send(session, 'OK ' + VERSION + '\n');
            continue;
        }
        handleFrame(session, line);
        if (session.phase === 'shell') return;
    }
}

function handleConnection(socket, remote) {
    activeSessions++;
    var session = {
        id: ++nextSessionId,
        socket: socket,
        remote: remote,
        phase: 'greeting',
        buffer: '',
        nonce: crypto.randomBytes(32).toString('hex'),
        shell: null,
        timer: null
    };
    socket.setNoDelay(true);
    send(session, 'KANT-ROOT/1 ' + session.nonce + '\n');
    session.timer = setTimeout(function () {
        if (session.phase === 'greeting') {
            log('auth timeout from ' + remote);
            try { socket.destroy(); } catch (e) { }
        }
    }, AUTH_TIMEOUT_MS);
    socket.on('data', function (chunk) {
        try { handleData(session, chunk); }
        catch (e) { log('data handler error: ' + errorText(e)); socket.destroy(); }
    });
    socket.on('error', function (e) {
        log('socket error from ' + remote + ': ' + errorText(e));
    });
    socket.on('close', function () {
        if (session.timer) { clearTimeout(session.timer); session.timer = null; }
        activeSessions--;
        log('connection closed ' + remote);
    });
}

function shutdown(signal) {
    log('stopping (' + signal + ')');
    releaseLock();
    process.exit(0);
}

function main() {
    var who = identity();
    var allowNonRoot = process.env.KANT_ROOT_ALLOW_NONROOT === '1';
    if (who.uid !== 0 && !allowNonRoot) {
        log('refusing to run: uid=' + who.uid + ' (expected 0)');
        process.exit(1);
    }
    if (!isFinite(PORT) || PORT < 0 || PORT > 65535) {
        log('invalid port: ' + process.env.KANT_ROOT_PORT);
        process.exit(1);
    }
    if (!acquireLock()) {
        log('another daemon is already running');
        process.exit(0);
    }
    token = loadToken();
    try { fs.writeFileSync(PID_FILE, String(process.pid), { mode: 384 }); } catch (e) { }
    log('started pid=' + who.pid + ' uid=' + who.uid + ' euid=' + who.euid +
        ' cap=' + who.cap_eff + ' smack=' + who.smack +
        ' bind=' + BIND + ' port=' + PORT + ' label=' + (LABEL || 'unchanged'));
    process.on('SIGTERM', function () { shutdown('SIGTERM'); });
    process.on('SIGINT', function () { shutdown('SIGINT'); });
    process.on('exit', function () { releaseLock(); });
    process.on('uncaughtException', function (e) {
        log('uncaught: ' + errorText(e));
        process.exit(1);
    });

    var server = net.createServer(function (socket) {
        if (activeSessions >= MAX_SESSIONS) {
            try { socket.end('BUSY\n'); } catch (e) { }
            return;
        }
        var remote = String(socket.remoteAddress || '?') + ':' + String(socket.remotePort || '?');
        log('connection from ' + remote);
        handleConnection(socket, remote);
    });
    server.on('error', function (e) {
        log('server error: ' + errorText(e));
        process.exit(1);
    });
    server.listen(PORT, BIND, function () {
        var actual = server.address();
        var port = actual && actual.port ? actual.port : PORT;
        log('listening on ' + BIND + ':' + port);
        if (PORT_FILE) {
            try { fs.writeFileSync(PORT_FILE, String(port), { mode: 384 }); }
            catch (e) { log('port file error: ' + errorText(e)); }
        }
    });
}

main();
