'use strict';

// a simple script for manually loading `index.js` into Frida

global._debug = true;
const Swift = require('./index');
const mangling = require('./mangling');
Object.defineProperty(global, 'Swift', {
    value: Swift,
    configurable: true,
    enumerable: true,
});
