'use strict';

// a simple script for manually loading `index.js` into Frida, as well as some test code

global._debug = true;
const Swift = require('./index');
Object.defineProperty(global, 'Swift', {
    value: Swift,
    configurable: true,
    enumerable: true,
});



var all_fns = {};
var func_locs = {};
Process.enumerateModulesSync().forEach(function(m) {
    Module.enumerateExportsSync(m.name).map(function(x) {
        if (x.name.startsWith("_T"))
            return [Swift.demangle(x.name), x.address];
        else
            return [x.name, x.address];
    }).forEach(function(name) {
        all_fns[name[0]] = name[1];
        func_locs[name[0]] = m.name;
    });
});
Swift.getClassMetadata().length;
