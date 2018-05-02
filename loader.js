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



//console.log(Swift.enumerateTypesSync().filter(x => x.toString().indexOf("Any") !== -1).join("\n"));
//var t = Swift._typesByName.get("Foo.ViewController"); var testVar = new t(Module.findExportByName("Foo", "_T04Foo7testVarAA14ViewControllerCSgv")); console.log(testVar.toString())
