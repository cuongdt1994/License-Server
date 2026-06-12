'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const settings = fs.readFileSync(path.join(__dirname, '..', 'views', 'settings.ejs'), 'utf8');

assert.match(settings, /Runtime Storage/);
assert.match(settings, /dataDir/);
assert.match(settings, /dataDirSource/);
assert.match(settings, /dataDirLocalFile/);
assert.match(settings, /Runtime Status/);
assert.match(settings, /runtime\.webPort/);
assert.match(settings, /runtime\.tcpPort/);
assert.match(settings, /runtime\.bindHost/);
assert.match(settings, /runtime\.pm2/);
assert.match(settings, /runtimeWarnings/);
assert.match(settings, /Session secret/);
assert.match(settings, /TCP secret/);
assert.match(settings, /runtime\.secretSources/);
assert.match(settings, /runtime\.secretFile/);

console.log('ui settings runtime tests passed');
