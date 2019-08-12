import * as _ from 'underscore';
import * as net from 'net';
import {SocksClient} from 'socks';
import * as punycode from 'punycode';
import {Socket} from 'net';
import {SocksClientEstablishedEvent, SocksProxyType} from 'socks/typings/common/constants';
import * as optimist from 'optimist';

import SERVERS from './Servers';

const REGEX_TEXT_BEFORE_TLD = /^.+?(\.|$)/;
const REGEX_MATCH = /(ReferralServer|Registrar Whois|Whois Server|WHOIS Server|Registrar WHOIS Server):[^\S\n]*((?:r?whois|https?):\/\/)?(.*)/;

interface Proxy {
  ipaddress: string;
  port: number;
  type: SocksProxyType;
}

interface Server {
  host: string;
  port: number;
  query: string;
  punycode?: string;
}

interface Options {
  server?: string | Server;
  follow?: number;
  timeout?: number;
  verbose?: boolean;
  bind?: string;
  proxy?: string | Proxy;
  encoding?: string;
  punycode?: boolean;
}

export async function lookup(addr: string, options: Options = {}): Promise<string | { server: string, data: string }[]> {
  return new Promise<{ server: string, data: string }[] | string>
  (async (resolve: (value?: string | PromiseLike<string> | { server: string, data: string }[]) => void,
          reject: (reason?: Error) => void) => {

    _.defaults(options, {
          follow: 2,
          timeout: 60000,
        },
    ); // 60 seconds in ms

    let server: Server;
    if (typeof options.server === 'string') {
      const splitted = options.server.split(':');
      server = {
        host: splitted[0],
        port: splitted.length === 2 ? parseInt(splitted[1], 10) : 43,
        query: '$addr\r\n',
      };
    } else if (typeof options.server === 'object') {
      server = options.server;
    }

    let proxy: Proxy;
    if (typeof options.proxy === 'string') {
      const split = options.proxy.split(':');
      proxy = {
        ipaddress: split[0],
        port: parseInt(split[1], 10),
        type: 5,
      };
    } else {
      proxy = options.proxy;
    }

    const {timeout} = options;

    if (!server || !server.host) {
      switch (true) {
        case addr.includes('@'):
          throw new Error('lookup: email addresses not supported');

        case !!net.isIP(addr):
          server = {
            host: SERVERS._.ip.host,
            query: SERVERS._.ip.query,
            port: 43,
          };
          break;

        default:
          let tld = punycode.toASCII(addr);
          let serverHost: { host: string, port: number, query: string } | string = '';
          while (!(!tld || serverHost)) {
            serverHost = (SERVERS as any)[tld];
            tld = tld.replace(REGEX_TEXT_BEFORE_TLD, '');
          }
          server = {
            host: (typeof serverHost === 'string' ? serverHost : serverHost.host),
            port: (typeof serverHost === 'string' ? 43 : serverHost.port),
            query: (typeof serverHost === 'string' ? '$addr\r\n' : serverHost.query),
          };
      }
    }

    if (!server) {
      throw new Error('lookup: no whois server is known for this kind of object');
    }

    if (proxy && typeof proxy === 'string') {
      const splitted = ('' + proxy).split(':');
      proxy = {
        ipaddress: splitted[0],
        port: parseInt(splitted[1], 10),
        type: 5,
      };
    }

    _.defaults(server, {
          port: 43,
          query: '$addr\r\n',
        },
    );

    if (proxy) {
      _.defaults(proxy,
          {type: 5});
    }

    async function _lookup(socket: Socket) {
      let idn = addr;
      if ((server.punycode) && (options.punycode)) {
        idn = punycode.toASCII(addr);
      }
      if (options.encoding) {
        socket.setEncoding(options.encoding);
      }
      socket.write(server.query.replace('$addr', idn));

      let data = '';
      socket.on('data', (chunk) => {
        data += chunk;
      });

      socket.on('timeout', () => {
        socket.destroy();
        reject(new Error('lookup: timeout'));
      });

      socket.on('error', (err) => {
        reject(err);
      });

      socket.on('close', () => {
        if (options.follow > 0) {
          const match = data.replace(/\r/gm, '').match(REGEX_MATCH);
          if ((match != null) && (match[3] !== server.host)) {
            options = _.extend({}, options, {
                  follow: options.follow - 1,
                  server: match[3].trim(),
                },
            );
            lookup(addr, options).then(() => {
              if (options.verbose) {
                resolve([{
                      server: server.host.trim(),
                      data,
                    },
                    ],
                );
              } else {
                resolve(data);
              }
            }).catch((err: Error) => {
              reject(err);
            });
            return;
          }
        }

        if (options.verbose) {
          resolve([{
            server: server.host.trim(),
            data,
          },
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
              port: server.port,
            },
            command: 'connect',
            timeout,
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
      await _lookup(socket);
    }
  });
}

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
    bind: optimist.argv.bind,
  }).then((data: { server: string, data: string }[] | string) => {
    if (_.isArray(data)) {
      return (() => {
        const result = [];
        for (const part of data) {
          console.log(part.server);
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
