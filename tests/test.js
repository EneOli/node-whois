const _ = require('underscore');
const assert = require('assert');
const whois = require('../dist/lib/index');

describe('#lookup()', function () {
  console.log('----- WATCH YOUR DAILY LIMIT! ------')
  this.timeout(10000);
  it('should work with google.com', (done) => {
    whois.lookup('google.com').then((data) => {
      assert.notStrictEqual(data.toLowerCase().indexOf('domain name: google.com'), -1);
      return done();
    }).catch((err) => {
      assert.ifError(err);
      return done();
    });
  });

  it('should work with 50.116.8.109', (done) => {
    whois.lookup('50.116.8.109').then((data) => {
      assert.notStrictEqual(data.toLowerCase().indexOf('netname:        linode-us'), -1);
      return done();
    }).catch((err) => {
      assert.ifError(err);
      return done();
    });
  });

  it('should work with 2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d', (done) => {
    whois.lookup('2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d').then((data) => {
      assert.strictEqual(data.toLowerCase().indexOf('cidr:           2001:C00::/23'), -1);
      return done();
    }).catch((err) => {
      assert.ifError(err);
      return done();
    });
  });

  it('should honor specified WHOIS server', (done) => {
    whois.lookup('gandi.net', {server: 'whois.gandi.net'}).then((data) => {
      data = data.toLowerCase();
      assert.notStrictEqual(data.indexOf('whois server: whois.gandi.net'), -1);
      assert.notStrictEqual(data.indexOf('domain name: gandi.net'), -1);
      return done();
    }).catch((err) => {
      assert.ifError(err);
      return done();
    });
  });

  it('should honor specified WHOIS server with port override', (done) => {
    whois.lookup('tucows.com', {server: 'whois.tucows.com:43'}).then((data) => {
      data = data.toLowerCase();
      assert.notStrictEqual(data.indexOf('whois server: whois.tucows.com'), -1);
      assert.notStrictEqual(data.indexOf('domain name: tucows.com'), -1);
      return done();
    }).catch((err) => {
      assert.ifError(err);
      return done();
    });
  });

  it('should follow specified number of redirects for domain', (done) => {
    whois.lookup('google.com', {follow: 1}).then((data) => {
      assert.notStrictEqual(data.toLowerCase().indexOf('domain name: google.com'), -1);
      return done();
    }).catch((err) => {
      assert.ifError(err);
      return done();
    });
  });

  it('should follow specified number of redirects for IP address', (done) => {
    whois.lookup('176.58.115.202', {follow: 1}).then((data) => {
      assert.notStrictEqual(data.toLowerCase().indexOf('cidr:           176.0.0.0/8'), -1);
      return done();
    }).catch((err) => {
      assert.ifError(err);
      return done();
    })
  });

  it('should work with verbose option', (done) => {
    whois.lookup('google.com', {verbose: true}).then((data) => {
      assert.strictEqual(data[0].server, 'whois.verisign-grs.com');
      assert.notStrictEqual(data[0].data.toLowerCase().indexOf('domain name: google.com'), -1);
      return done();
    }).catch((err) => {
      assert.ifError(err);
      return done();
    });
  });

  it('should work with nic.sh', done => {
    whois.lookup('nic.sh').then((data) => {
      assert.notStrictEqual(data.toLowerCase().indexOf('registry domain id: d503300000040403495-lrms'), -1);
      return done();
    }).catch((err) => {
      assert.ifError(err);
      return done();
    })
  });

  it('should work with nic.io', (done) => {
    whois.lookup('nic.io').then((data) => {
      assert.notStrictEqual(data.toLowerCase().indexOf('registry domain id: d503300000040453277-lrms'), -1);
      return done();
    }).catch((err) => {
      assert.ifError(err);
      return done();
    })
  });

  it('should work with nic.ac', (done) => {
    whois.lookup('nic.ac').then((data) => {
      assert.notStrictEqual(data.toLowerCase().indexOf('registry domain id: d503300000040632620-lrms'), -1);
      return done();
    }).catch((err) => {
      assert.ifError(err);
      return done();
    })
  });

  it('should work with nic.tm', (done) => {
    whois.lookup('nic.tm').then((data) => {
      assert.notStrictEqual(data.toLowerCase().indexOf('status : permanent/reserved'), -1);
      return done();
    }).catch((err) => {
      assert.ifError(err);
      return done();
    });
  });

  it('should work with nic.global', (done) => {
    whois.lookup('nic.global').then((data) => {
      assert.notStrictEqual(data.toLowerCase().indexOf('registry domain id: d2836144-agrs'), -1);
      return done();
    }).catch((err) => {
      assert.ifError(err);
      return done();
    });
  });

  it('should work with srs.net.nz', (done) => {
    whois.lookup('srs.net.nz').then((data) => {
      assert.notStrictEqual(data.toLowerCase().indexOf('domain_name: srs.net.nz'), -1);
      return done();
    }).catch((err) => {
      assert.ifError(err);
      return done();
    });
  });

  it('should work with redundant follow', (done) => {
    whois.lookup('google.com', {follow: 5}).then((data) => {
      assert.notStrictEqual(data.toLowerCase().indexOf('domain name: google.com'), -1);
      return done();
    }).catch((err) => {
      assert.ifError(err);
      return done();
    });
  });

  it('should work with küche.de', (done) => {
    whois.lookup('küche.de').then((data) => {
      assert.notStrictEqual(data.toLowerCase().indexOf('domain: küche.de'), -1);
      assert.notStrictEqual(data.toLowerCase().indexOf('status: connect'), -1);
      return done();
    }).catch((err) => {
      assert.ifError(err);
      return done();
    });
  });

  it('should work with google.co.jp in english', (done) => {
    whois.lookup('google.co.jp').then((data) => {
      assert.notStrictEqual(data.toLowerCase().indexOf('a. [domain name]                google.co.jp'), -1);
      return done();
    }).catch((err) => {
      assert.ifError(err);
      return done();
    });
  });

  it('should work with registry.pro', (done) => {
    whois.lookup('registry.pro').then((data) => {
      assert.notStrictEqual(data.toLowerCase().indexOf('domain id: d107300000000006392-lrms'), -1);
      return done();
    }).catch((err) => {
      assert.ifError(err);
      return done();
    });
  });

  it('should fail with google.com due to timeout', (done) => {
    whois.lookup('google.com', {timeout: 1}).then((data) => {
      return done();
    }).catch((err) => {
      assert.strictEqual('lookup: timeout', err.message);
      assert(err);
      return done();
    })
  });

  it('should succeed with google.com with timeout', (done) => {
    whois.lookup('google.com', {timeout: 10000}).then((data) => {
      assert.notStrictEqual(data.toLowerCase().indexOf('domain name: google.com'), -1);
      return done();
    }).catch((err) => {
      assert.ifError(err);
      return done();
    });
  });

  it('should work with åre.no', (done) => {
    whois.lookup('åre.no').then((data) => {
      assert.notStrictEqual(data.toLowerCase().indexOf('åre.no'), -1);
      return done();
    }).catch((err) => {
      assert.ifError(err);
      return done();
    });
  });

  it('should work with nic.digital', (done) => {
    whois.lookup('nic.digital').then((data) => {
      assert.notStrictEqual(data.toLowerCase().indexOf('nic.digital'), -1);
      return done();
    }).catch((err) => {
      assert.ifError(err);
      return done();
    });
  });

  it('should work with whois.nic.ai', (done) => {
    whois.lookup('whois.nic.ai').then((data) => {
      assert.notStrictEqual(data.toLowerCase().indexOf('whois.nic.ai'), -1);
      return done();
    }).catch((err) => {
      assert.ifError(err);
      return done();
    });
  });

  it('should work with currentzoology.org', (done) => {
    whois.lookup('currentzoology.org').then((data) => {
      assert.notStrictEqual(data.toLowerCase().indexOf('currentzoology.org'), -1);
      return done();
    }).catch((err) => {
      assert.ifError(err);
      return done();
    });
  });

  return it('should work with 148.241.109.161', (done) => {
    whois.lookup('148.241.109.161', {encoding: 'binary'}).then((data) => {
      assert.strictEqual(data.indexOf('Instituto Tecnológico'), -1);
      return done();
    }).catch((err) => {
      assert.ifError(err);
      return done();
    })
  });
});