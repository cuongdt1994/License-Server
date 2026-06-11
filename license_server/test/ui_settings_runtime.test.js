'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const settings = fs.readFileSync(path.join(__dirname, '..', 'views', 'settings.ejs'), 'utf8');

assert.match(settings, /Runtime Storage/);
assert.match(settings, /dataDir/);
assert.match(settings, /dataDirSource/);
assert.match(settings, /dataDirLocalFile/);

console.log('ui settings runtime tests passed');
