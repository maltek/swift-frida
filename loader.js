'use strict';

// a simple script for manually loading `index.js` into Frida, as well as some test code

global._debug = true;
const Swift = require('./index');
const mangling = require('./mangling');
Object.defineProperty(global, 'Swift', {
    value: Swift,
    configurable: true,
    enumerable: true,
});



var all_fns = {};
var func_locs = {};
Process.enumerateModulesSync().forEach(function(m) {
    Module.enumerateExportsSync(m.name).map(function(x) {
        if (x.name.startsWith(mangling.MANGLING_PREFIX))
            return [Swift.demangle(x.name), x.address];
        else
            return [x.name, x.address];
    }).forEach(function(name) {
        all_fns[name[0]] = name[1];
        func_locs[name[1]] = m.name;
    });
});
global.all_fns = all_fns;
global.func_locs = func_locs;
console.log(Swift.enumerateTypesSync().filter(x => x.indexOf("bool") !== -1).join("\n"));
