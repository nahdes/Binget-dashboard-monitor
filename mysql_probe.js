#!/usr/bin/env node
// Diagnostic: mirrors pm2-monitor.js's checkMysql() exactly, but prints what it actually
// receives instead of just true/false, so we can see WHY it's failing.
//
// Usage: node mysql_probe.js <host> <port> [timeoutMs]
// Example: node mysql_probe.js 10.0.102.65 3306 6000

const net = require('net');

const host = process.argv[2];
const port = parseInt(process.argv[3], 10);
const timeoutMs = parseInt(process.argv[4] || '6000', 10);

if (!host || !port) {
  console.error('Usage: node mysql_probe.js <host> <port> [timeoutMs]');
  process.exit(1);
}

console.log(`Connecting to ${host}:${port} (timeout ${timeoutMs}ms)...`);

const start = Date.now();
let buf = Buffer.alloc(0);
let settled = false;

const socket = net.createConnection({ host, port, timeout: timeoutMs });

socket.once('connect', () => {
  console.log(`TCP connected in ${Date.now() - start}ms. Waiting for server to send data (we send nothing)...`);
});

socket.on('data', chunk => {
  buf = Buffer.concat([buf, chunk]);
  console.log(`Received ${chunk.length} bytes (total ${buf.length}). Hex so far:`);
  console.log(buf.toString('hex').match(/.{1,32}/g).join('\n'));

  if (buf.length >= 5) {
    settled = true;
    const protocolVersion = buf[4];
    console.log(`\nByte[4] (protocol version) = 0x${protocolVersion.toString(16).padStart(2, '0')}`);
    console.log(protocolVersion === 0x0a || protocolVersion === 0x09
      ? '\n✅ This LOOKS like a valid MySQL/MariaDB handshake — checkMysql() should report ONLINE.'
      : '\n❌ This does NOT look like a MySQL/MariaDB handshake packet — something else is answering on this port, or it is proxied/wrapped.');
    socket.destroy();
    process.exit(0);
  }
});

socket.once('timeout', () => {
  if (settled) return;
  console.log(`\n⏱️  TIMEOUT after ${timeoutMs}ms — connected via TCP but the server never sent any data.`);
  console.log('This usually means: a proxy/load balancer is accepting the TCP connection without');
  console.log('actually forwarding to MariaDB, MariaDB has hit max_connections and is silently');
  console.log('holding the socket, or something non-MySQL is listening on this port.');
  socket.destroy();
  process.exit(1);
});

socket.once('error', err => {
  if (settled) return;
  console.log(`\n❌ Connection error: ${err.message}`);
  process.exit(1);
});