'use strict';

const assert = require('assert');
const { buildRuntimeConfig } = require('../runtime_config');

{
    const cfg = buildRuntimeConfig({
        env: {
            WEB_PORT: '8088',
            TCP_PORT: '28015',
            LICENSE_BIND_HOST: '127.0.0.1',
            LICENSE_DATA_DIR: 'C:\\license-data',
            pm_id: '3',
            name: 'license-server',
            PM2_HOME: 'C:\\pm2',
            LICENSE_COOKIE_SECURE: '1',
        },
    });

    assert.equal(cfg.webPort, 8088);
    assert.equal(cfg.tcpPort, 28015);
    assert.equal(cfg.bindHost, '127.0.0.1');
    assert.equal(cfg.pm2.enabled, true);
    assert.equal(cfg.pm2.id, '3');
    assert.equal(cfg.pm2.name, 'license-server');
    assert.equal(cfg.cookieSecure, true);
    assert.deepEqual(cfg.warnings, []);
}

{
    const cfg = buildRuntimeConfig({ env: {} });

    assert.equal(cfg.webPort, 5000);
    assert.equal(cfg.tcpPort, 27015);
    assert.equal(cfg.bindHost, '0.0.0.0');
    assert.equal(cfg.cookieSecure, false);
    assert.equal(cfg.pm2.enabled, false);
    assert.ok(cfg.warnings.includes('LICENSE_DATA_DIR is not set; runtime data may live inside the app directory.'));
}

{
    const cfg = buildRuntimeConfig({ env: { NODE_ENV: 'production', LICENSE_COOKIE_SECURE: '0' } });
    assert.equal(cfg.cookieSecure, false);
}

{
    assert.throws(
        () => buildRuntimeConfig({ env: { WEB_PORT: 'abc' } }),
        /WEB_PORT must be a number between 1 and 65535/
    );
    assert.throws(
        () => buildRuntimeConfig({ env: { TCP_PORT: '70000' } }),
        /TCP_PORT must be a number between 1 and 65535/
    );
}

console.log('runtime config tests passed');
