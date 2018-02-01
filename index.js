"use strict";

/* jshint esnext: true, evil: true */

let size_t = Process.pointerSize == 8 ? 'uint64' : Process.pointerSize == 4 ? 'uint32' : "unsupported platform";


let _api = null;
function getApi() {
    if (_api !== null) {
        return _api;
    }

    const temporaryApi = {};
    const pending = [
        {
            module: "libsystem_malloc.dylib",
            functiions: {
                "free": ['void', ['pointer']],
            }
        },
        {
            // see https://github.com/apple/swift/blob/master/docs/Runtime.md
            module: "libswiftCore.dylib",
            functions: {
                /*"objc_msgSend": function (address) {
                    this.objc_msgSend = address;
                },*/
                "swift_demangle": ['pointer', ['pointer', size_t, 'pointer', 'pointer', 'int32']],
                //'swift_allocObject': ['pointer', ['pointer', size_t, size_t]],
                'swift_allocBox': [['pointer', 'pointer'], ['pointer']],
                'swift_deallocBox': ['void', ['pointer']],
                'swift_stringFromUTF8InRawMemory': ['void', ['pointer', 'pointer', size_t]],

                "swift_getTupleTypeMetadata": ['pointer', [size_t, 'pointer', 'pointer', 'pointer']],
                //"swift_getTupleTypeMetadata2": ['pointer', ['pointer', 'pointer', 'pointer', 'pointer']],
                //"swift_getTupleTypeMetadata3": ['pointer', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']],
                "swift_getExistentialMetatypeMetadata": ['pointer', ['pointer']],
                "swift_getExistentialTypeMetadata": ['pointer', [size_t, 'pointer', size_t, 'pointer']],
                'swift_getGenericMetadata': ['pointer', ['pointer', 'pointer']],
                "swift_getObjCClassMetadata": ['pointer', ['pointer']],
                "swift_getFunctionTypeMetadata": ['pointer', [size_t, 'pointer', 'pointer', 'pointer']],
                //"swift_getFunctionTypeMetadata1": ['pointer', [size_t, 'pointer', 'pointer']],
                //"swift_getFunctionTypeMetadata2": ['pointer', [size_t, 'pointer', 'pointer', 'pointer']],
                //"swift_getFunctionTypeMetadata3": ['pointer', [size_t, 'pointer', 'pointer', 'pointer', 'pointer']],
                "swift_getForeignTypeMetadata": ['pointer', ['pointer']],
                "swift_getMetatypeMetadata": ['pointer', ['pointer']],
                "swift_getTypeByName": ['pointer', ['pointer', size_t]]
            },
            // optionals are functions/variables that might not be available
            optionals: {
                "free": "leaks don't break functionality",
            }
        }
    ];
    let remaining = 0;
    pending.forEach(function (api) {
        const functions = api.functions || {};
        const variables = api.variables || {};
        const optionals = api.optionals || {};

        remaining += Object.keys(functions).length + Object.keys(variables).length;

        const exportByName = Module
        .enumerateExportsSync(api.module)
        .reduce(function (result, exp) {
            result[exp.name] = exp;
            return result;
        }, {});

        Object.keys(functions)
        .forEach(function (name) {
            const exp = exportByName[name];
            if (exp !== undefined && exp.type === 'function') {
                const signature = functions[name];
                if (typeof signature === 'function') {
                    signature.call(temporaryApi, exp.address);
                } else {
                    temporaryApi[name] = new NativeFunction(exp.address, signature[0], signature[1]);
                }
                remaining--;
            } else {
                const optional = optionals[name];
                if (optional)
                    remaining--;
            }
        });

        Object.keys(variables)
        .forEach(function (name) {
            const exp = exportByName[name];
            if (exp !== undefined && exp.type === 'variable') {
                const handler = variables[name];
                handler.call(temporaryApi, exp.address);
                remaining--;
            }
        });
    });
    if (remaining === 0) {
        _api = temporaryApi;
    } else {
        throw Error("missing functions from Swift runtime: " + remaining);
    }

    return _api;
}

function jsStringToSwift(val) {
    let cStr = Memory.allocUtf8String(val);
    const sizeOfString = Memory.pointerSize * 3;
    let swiftStr = Memory.alloc(sizeOfString);
    api.swift_stringFromUTF8InRawMemory(swiftStr, cStr, val.length);
    return swiftStr;
}

module.exports = {

    get available() {
        return Module.findBaseAddress("libswiftCore.dylib") !== null;
    },

    isSwiftFunction(func) {
        let name = func.name || func;
        return name.startsWith('_T');
    },

    demangle(name) {
        if (!this.isSwiftFunction(name))
            throw Error("function name is not a mangled Swift function");

        let cStr = Memory.allocUtf8String(name);
        let demangled = this._api.swift_demangle(cStr, name.length, ptr(0), ptr(0), 0);
        let res = Memory.readUtf8String(demangled);
        if ("free" in this._api)
            this._api.free(demangled);
        return res;
    },

    use(name) {
        let cStr = Memory.allocUtf8String(name);
        let type = this._api.swift_getTypeByName(name, name.length);
        return type;
    },

    get _api() {
        if (!this.available)
            return null;

        return getApi();
    },
};
