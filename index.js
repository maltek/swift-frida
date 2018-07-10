"use strict";

/* jshint esnext: true, evil: true */

const metadata = require('./metadata');
const types = require('./types');
const mangling = require('./mangling');
const runtime = require('./runtime-api');



let Swift;
Swift = module.exports = {

    get available() {
        if (Module.findBaseAddress("libswiftCore.dylib") === null)
            return false;
        try {
            runtime.api;
            return true;
        } catch(_) {
        }
        return false;
    },

    isSwiftName(symbol) {
        return mangling.isSwiftName(symbol);
    },

    // like Interceptor.attach, but with type information, so you get nice wrappers around the Swift values
    /*hook(target, callbacks, signature) {
        let interceptorCallbacks = {};
        if ("onEnter" in callbacks) {
            interceptorCallbacks.onEnter = function(args) {
                callbacks.onEnter([]);
            };
        }
        if ("onLeave" in callbacks) {
            interceptorCallbacks.onLeave = function(retval) {
                callbacks.onLeave(null);
            };
        }
        Interceptor.attach(target, interceptorCallbacks);
    },*/

    // does not actually mangle the name, only has a lookup table with all names that have been demangled earlier
    getMangled(name) {
        return mangling.knownMangled.get(name);
    },

    demangle(name) {
        return mangling.demangle(name);
    },

    enumerateTypesSync(library) {
        return types.findAllTypes(library);
    },

    makeTupleType(labels, innerTypes) {
        return types.makeTupleType(labels, innerTypes);
    },

    makeFunctionType(args, returnType, flags) {
        let data = Memory.alloc(Process.pointerSize * (2 + args.length));

        let writeFlags = ptr(args.length).and(metadata.TargetFunctionTypeFlags.NumArgumentsMask);
        if (flags && flags.doesThrow)
            writeFlags = writeFlags.or(ptr(metadata.TargetFunctionTypeFlags.ThrowsMask));
        if (flags && flags.convention)
            writeFlags = writeFlags.or(ptr(metadata.FunctionMetadataConvention[flags.convention] << metadata.TargetFunctionTypeFlags.ConventionShift));

        Memory.writePointer(data, writeFlags);

        for (let i = 0; i < args.length; i++) {
            let val;
            if ("canonicalType" in args[i])
                val = args[i].canonicalType._ptr;
            else {
                val = args[i].type.canonicalType._ptr;
                if (args[i].inout)
                    val = val.or(1);
            }
            Memory.writePointer(data.add((i + 1) * Process.pointerSize), val);
        }
        if (returnType === null)
            returnType = this.makeTupleType([], []); // Void
        Memory.writePointer(data.add((args.length + 1) * Process.pointerSize), returnType.canonicalType._ptr);

        let pointer = this._api.swift_getFunctionTypeMetadata(data);
        return new types.Type(null, new metadata.TargetMetadata(pointer));
    },

    // Create a new types.Type object, from a Metadata*.
    // The name is only used for opaque types (builtins).
    _typeFromCanonical(pointer, name) {
        return new types.Type(null, new metadata.TargetMetadata(pointer), name);
    },

    get _api() {
        if (!this.available)
            return null;
        return runtime.api;
    },
};
