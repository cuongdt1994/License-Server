'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { resolveDataDir } = require('../data_dir');

function tmp() {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'license-data-dir-'));
}

{
    const appDir = tmp();
    const dir = resolveDataDir({ appDir, env: {} });
    assert.strictEqual(dir, path.join(appDir, 'data'));
}

{
    const appDir = tmp();
    const dataDir = path.join(tmp(), 'state');
    const dir = resolveDataDir({ appDir, env: { LICENSE_DATA_DIR: dataDir } });
    assert.strictEqual(dir, dataDir);
    assert.ok(fs.statSync(dir).isDirectory());
}

{
    const appDir = tmp();
    const dataDir = path.join(tmp(), 'state-case-alias');
    const dir = resolveDataDir({ appDir, env: { License_DATA_DIR: dataDir } });
    assert.strictEqual(dir, dataDir);
    assert.ok(fs.statSync(dir).isDirectory());
}

{
    const appDir = tmp();
    const dataDir = path.join(tmp(), 'state-local-file');
    fs.writeFileSync(path.join(appDir, 'data_dir.local'), `${dataDir}\n`);
    const dir = resolveDataDir({ appDir, env: {} });
    assert.strictEqual(dir, dataDir);
    assert.ok(fs.statSync(dir).isDirectory());
}

{
    const appDir = tmp();
    const envDir = path.join(tmp(), 'state-env-priority');
    const localDir = path.join(tmp(), 'state-local-lower-priority');
    fs.writeFileSync(path.join(appDir, 'data_dir.local'), `${localDir}\n`);
    const dir = resolveDataDir({ appDir, env: { LICENSE_DATA_DIR: envDir } });
    assert.strictEqual(dir, envDir);
}

{
    const appDir = tmp();
    const dataDir = path.join(tmp(), 'state-autoremember');
    const dir = resolveDataDir({ appDir, env: { LICENSE_DATA_DIR: dataDir } });
    assert.strictEqual(dir, dataDir);
    assert.strictEqual(fs.readFileSync(path.join(appDir, 'data_dir.local'), 'utf8').trim(), dataDir);
}

assert.throws(
    () => resolveDataDir({ appDir: tmp(), env: { LICENSE_DATA_DIR: 'relative-data' } }),
    /absolute path/
);

assert.throws(
    () => {
        const appDir = tmp();
        fs.writeFileSync(path.join(appDir, 'data_dir.local'), 'relative-data\n');
        resolveDataDir({ appDir, env: {} });
    },
    /absolute path/
);

assert.throws(
    () => {
        const appDir = tmp();
        resolveDataDir({ appDir, env: { LICENSE_DATA_DIR: path.join(appDir, 'data') } });
    },
    /outside license_server/
);

console.log('data_dir tests passed');
