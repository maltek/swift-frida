"use strict";

/* jshint esnext: true, evil: true */

let api;

module.exports = {
    MANGLING_PREFIX: "_T", // 'old' mangling -- Swift HEAD has switched to using "_S"

    isSwiftName(symbol) {
        let name = symbol.name || symbol;
        return name.startsWith(this.MANGLING_PREFIX);
    },

    knownMangled: new Map(),
    demangle(name) {
        if (!this.isSwiftName(name))
            throw new Error("function name '" + name + "' is not a mangled Swift function");

        let cStr = Memory.allocUtf8String(name);
        let demangled = api.swift_demangle(cStr, name.length, ptr(0), ptr(0), 0);
        let res = Memory.readUtf8String(demangled);
        if ("free" in api)
            api.free(demangled);

        this.knownMangled.set(res, name);

        return res;
    },
    demangleIfSwift(name) {
        if (this.isSwiftName(name))
            return this.demangle(name);
        else
            return name;
    },
};
api = require('./runtime-api').api;
