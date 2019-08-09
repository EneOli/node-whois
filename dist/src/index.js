"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
const _ = __importStar(require("underscore"));
const net = __importStar(require("net"));
const socks_1 = require("socks");
const punycode = __importStar(require("punycode"));
const optimist = __importStar(require("optimist"));
const SERVERS = __importStar(require("../servers.json"));
function lookup(addr, options) {
    return new Promise((resolve, reject) => {
        let parts;
        _.defaults(options, {
            follow: 2,
            timeout: 60000
        }); // 60 seconds in ms
        let { server } = options;
        let { proxy } = options;
        const { timeout } = options;
        if (!server) {
            switch (true) {
                case _.contains(addr, '@'):
                    throw new Error('lookup: email addresses not supported');
                case net.isIP(addr) !== 0:
                    server = SERVERS['_']['ip'];
                    break;
                default:
                    let tld = punycode.toASCII(addr);
                    while (true) {
                        server = SERVERS[tld];
                        if (!tld || server) {
                            break;
                        }
                        tld = tld.replace(/^.+?(\.|$)/, '');
                    }
            }
        }
        if (!server) {
            throw new Error('lookup: no whois server is known for this kind of object');
        }
        if (typeof server === 'string') {
            parts = server.split(':');
            server = {
                host: parts[0],
                port: parts[1]
            };
        }
        if (typeof proxy === 'string') {
            parts = proxy.split(':');
            proxy = {
                ipaddress: parts[0],
                port: parseInt(parts[1])
            };
        }
        _.defaults(server, {
            port: 43,
            query: "$addr\r\n"
        });
        if (proxy) {
            _.defaults(proxy, { type: 5 });
        }
        function _lookup(socket) {
            return __awaiter(this, void 0, void 0, function* () {
                let idn = addr;
                if ((server.punycode !== false) && (options.punycode !== false)) {
                    idn = punycode.toASCII(addr);
                }
                if (options.encoding) {
                    socket.setEncoding(options.encoding);
                }
                socket.write(server.query.replace('$addr', idn));
                let data = '';
                socket.on('data', chunk => {
                    return data += chunk;
                });
                socket.on('timeout', () => {
                    socket.destroy();
                    throw new Error('lookup: timeout');
                });
                socket.on('error', err => {
                    reject(err);
                });
                return socket.on('close', () => {
                    if (options.follow > 0) {
                        const match = data.replace(/\r/gm, '').match(/(ReferralServer|Registrar Whois|Whois Server|WHOIS Server|Registrar WHOIS Server):[^\S\n]*((?:r?whois|https?):\/\/)?(.*)/);
                        if ((match != null) && (match[3] !== server.host)) {
                            options = _.extend({}, options, {
                                follow: options.follow - 1,
                                server: match[3].trim()
                            });
                            lookup(addr, options).then(() => {
                                if (options.verbose) {
                                    resolve([{
                                            server: ('object' === typeof server) ? server.host.trim() : server.trim(),
                                            data
                                        }
                                    ].concat(parts));
                                }
                                else {
                                    return resolve(parts);
                                }
                            }).catch((err) => {
                                return reject(err);
                            });
                            return;
                        }
                    }
                    if (options.verbose) {
                        resolve([{
                                server: ('object' === typeof server) ? server.host.trim() : server.trim(),
                                data
                            }
                        ]);
                    }
                    else {
                        resolve(data);
                    }
                });
            });
        }
        if (proxy) {
            return socks_1.SocksClient.createConnection({
                proxy,
                destination: {
                    host: server.host,
                    port: server.port
                },
                command: 'connect',
                timeout
            }, (err, { socket }) => {
                if (err != null) {
                    reject(err);
                }
                if (timeout) {
                    socket.setTimeout(timeout);
                }
                _lookup(socket);
                return socket.resume();
            });
        }
        else {
            const sockOpts = {
                host: server.host,
                port: server.port,
                localAddress: '',
            };
            if (options.bind) {
                sockOpts.localAddress = options.bind;
            }
            const socket = net.connect(sockOpts);
            if (timeout) {
                socket.setTimeout(timeout);
            }
            return _lookup(socket);
        }
    });
}
exports.lookup = lookup;
;
if (module === require.main) {
    optimist.usage('$0 [options] address')
        .default('s', null)
        .alias('s', 'server')
        .describe('s', 'whois server')
        .default('f', 0)
        .alias('f', 'follow')
        .describe('f', 'number of times to follow redirects')
        .default('p', null)
        .alias('p', 'proxy')
        .describe('p', 'SOCKS proxy')
        .boolean('v')
        .default('v', false)
        .alias('v', 'verbose')
        .describe('v', 'show verbose results')
        .default('b', null)
        .alias('b', 'bind')
        .describe('b', 'bind to a local IP address')
        .boolean('h')
        .default('h', false)
        .alias('h', 'help')
        .describe('h', 'display this help message');
    if (optimist.argv.h) {
        console.log(optimist.help());
        process.exit(0);
    }
    if ((optimist.argv._[0] == null)) {
        console.log(optimist.help());
        process.exit(1);
    }
    lookup(optimist.argv._[0], {
        server: optimist.argv.server,
        follow: optimist.argv.follow,
        proxy: optimist.argv.proxy,
        verbose: optimist.argv.verbose,
        bind: optimist.argv.bind
    }).then((data) => {
        if (_.isArray(data)) {
            return (() => {
                const result = [];
                for (const part of data) {
                    if (typeof part.server === 'object') {
                        console.log(part.server.host);
                    }
                    else {
                        console.log(part.server);
                    }
                    console.log(part.data);
                    result.push(console.log);
                }
                return result;
            })();
        }
        else {
            return console.log(data);
        }
    }).catch((err) => {
        console.log(err);
        process.exit(1);
    });
}
//# sourceMappingURL=index.js.map