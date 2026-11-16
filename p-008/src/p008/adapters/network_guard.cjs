// Fixed Node guard: no network connections or DNS, including loopback.
const net = require('node:net');
const tls = require('node:tls');
const dns = require('node:dns');
const deny = () => { throw new Error('P008-OFFLINE-NETWORK-DISABLED'); };
net.Socket.prototype.connect = deny;
net.Server.prototype.listen = deny;
tls.connect = deny;
for (const key of ['lookup', 'resolve', 'resolve4', 'resolve6', 'reverse']) dns[key] = deny;
for (const key of ['lookup', 'resolve', 'resolve4', 'resolve6', 'reverse']) dns.promises[key] = deny;
require('node:dgram').createSocket = deny;
