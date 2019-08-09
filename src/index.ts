import * as _ from 'underscore';
import * as net from 'net';
import {SocksClient} from 'socks';
import * as punycode from 'punycode';
import {Socket} from "net";
import {SocksClientEstablishedEvent} from "socks/typings/common/constants";
import * as optimist from 'optimist';

import * as SERVERS from '../servers.json'

export function lookup(addr: any, options: any): Promise<any> {
  return new Promise((resolve, reject) => {
    let parts: any[];

    _.defaults(options, {
          follow: 2,
          timeout: 60000
        }
    ); // 60 seconds in ms

    let {server} = options;
    let {proxy} = options;
    const {timeout} = options;

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
            server = (SERVERS as any)[tld];
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
        }
    );

    if (proxy) {
      _.defaults(proxy,
          {type: 5});
    }


    async function _lookup(socket: Socket) {
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
                }
            );
            lookup(addr, options).then(() => {
              if (options.verbose) {
                resolve([{
                      server: ('object' === typeof server) ? server.host.trim() : server.trim(),
                      data
                    }
                    ].concat(parts)
                );
              } else {
                return resolve(parts);
              }
            }).catch((err: Error) => {
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
        } else {
          resolve(data);
        }
      });
    }

    if (proxy) {
      return SocksClient.createConnection({
            proxy,
            destination: {
              host: server.host,
              port: server.port
            },
            command: 'connect',
            timeout
          }
          , (err: Error, {socket}: SocksClientEstablishedEvent) => {
            if (err != null) {
              reject(err);
            }
            if (timeout) {
              socket.setTimeout(timeout);
            }

            _lookup(socket);

            return socket.resume();
          });

    } else {
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
};


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
  }).then((data: any[] | string) => {
    if (_.isArray(data)) {
      return (() => {
        const result = [];
        for (const part of data) {
          if (typeof part.server === 'object') {
            console.log(part.server.host);
          } else {
            console.log(part.server);
          }
          console.log(part.data);
          result.push(console.log);
        }
        return result;
      })();

    } else {
      return console.log(data);
    }
  }).catch((err: Error) => {
    console.log(err);
    process.exit(1);
  });
}
