"use strict";

/* jshint esnext: true, evil: true */

let types = require('./types');

let size_t = Process.pointerSize === 8 ? 'uint64' : Process.pointerSize === 4 ? 'uint32' : "unsupported platform";


let _api = null;


// reads a Swift `String` from a NativePointer or an args-like array of NativePointers
function readSwiftString(data) {
    // TODO: use `Swift.String.utf8CString.getter`
}

// takes the JS string `str` and copies it to the NativePointer or args-like array of NativePointers in `dest`
function jsStringToSwift(str, dest) {
    let cStr = Memory.allocUtf8String(val);
    const sizeOfString = Process.pointerSize * 3;

    let swiftStr;
    if (data instanceof NativePointer) {
        swiftStr = data;
    } else {
        swiftStr = Memory.alloc(sizeOfString);
    }
    api.swift_stringFromUTF8InRawMemory(swiftStr, cStr, val.length);

    if (!(data instanceof NativePointer)) {
        dest[0] = Memory.readPointer(swiftStr);
        dest[1] = Memory.readPointer(swiftStr.add(Process.pointerSize));
        dest[2] = Memory.readPointer(swiftStr.add(Process.pointerSize * 2));
    }
}

/*function anyToString(any) {
// TODO: call String(reflecting: any).utf8CString
}*/

const OpaqueExistentialContainer = [
                                        ['pointer', 'pointer', 'pointer'], // void *fixedSizeBuffer[3];
                                        'pointer', // Metadata *type
                                        // WitnessTable *witnessTables[NUM_WITNESS_TABLES]; (depending on the number of protocols required for the type -- for the Any type, no witness tables should be there)
                                   ]

// Parses a function signature.
function Signature(demangledName) {
    let specializations = [];
    if (demangledName.startsWith("generic specialization <preserving fragile attribute, ")) {
        let match = demangledName.match(/^generic specialization <preserving fragile attribute, (.+)> of (.+)$/);
        specializations = match[1].split(/\s*,\s*/);
        demangledName = match[2];
    }

    let [, name, bounds, params, ret] = demangledName.match(/^([^(<]+)(?:<([^>]+)>)?\(([^)]+)\) -> (.+)$/);
    let genericParams = [], constraints = [];
    if (bounds !== undefined) {
        bounds = bounds.split(" where ");
        genericParams = bounds[0].split(/\s*,\s*/);
        constraints = bounds[1].split(/\s*,\s*/).map(c => {
            c = c.split(/\s*:\s*/);
            return {
                typeParam: c[0],
                constraint: c[1],
            };
        });
    }

    params = params.split(",").map(param => {
        param = param.split(/\s*:\s*/);
        return {
            name: params[0],
            type: params[1],
        };
    });

    this.name = name;
    this.specializations = specializations;
    this.genericParams = genericParams;
    this.typeConstraints = constraints;
    this.params = params;
    this.returnType = ret;
    this.throwing = false; // TODO
}
Signature.prototype = {
    get paramTypes() {
        this.params.map(p => p.type);
    }
};

module.exports = {

    get available() {
        return Module.findBaseAddress("libswiftCore.dylib") !== null;
    },

    isSwiftFunction(func) {
        let name = func.name || func;
        return name.startsWith('_T');
    },

    // like Interceptor.attach, but with type information, so you get nice wrappers around the Swift values
    hook(target, callbacks, signature) {
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
    },

    // extracts the argument and return types from a demangled function name like `Swift.Substring.UnicodeScalarView.index(after: Swift.String.Index) -> Swift.String.Index`
    //
    // Returns an object with properties `name`, `genericBounds`, `argTypes`, `returnType`.
    parseSignature(demangledName) {
        return new Signature(demangledName);
    },

    _mangled: new Map(),

    // does not actually mangle the name, only has a lookup table with all names that have been demangled earlier
    get_mangled(name) {
        return this._mangled.get(name);
    },

    demangle(name) {
        if (!this.isSwiftFunction(name))
            throw Error("function name is not a mangled Swift function");

        let cStr = Memory.allocUtf8String(name);
        let demangled = this._api.swift_demangle(cStr, name.length, ptr(0), ptr(0), 0);
        let res = Memory.readUtf8String(demangled);
        if ("free" in this._api)
            this._api.free(demangled);

        this._mangled.set(res, name);

        return res;
    },

    getClassMetadata() {
        /*// that function only supports classes:
        let cStr = Memory.allocUtf8String(name);
        let type = this._api.swift_getTypeByName(name, name.length);
        return type;*/
        // TODO: manually parse type data
        let sizeAlloc = Memory.alloc(8);
        let names = [];
        for (let mod of Process.enumerateModulesSync()) {
            let sections = [];
            const __TEXT = Memory.allocUtf8String("__TEXT");
            const __swift2_types = Memory.allocUtf8String("__swift2_types");
            const __swift2_proto = Memory.allocUtf8String("__swift2_proto");
            // we don't have to use the name _mh_execute_header to refer to the mach-o header -- it's the module header
            let pointer = this._api.getsectiondata(mod.base, __TEXT, __swift2_types, sizeAlloc);
            if (!pointer.isNull())
                sections.push(["types", pointer, Memory.readULong(sizeAlloc)]);
            pointer = this._api.getsectiondata(mod.base, __TEXT, __swift2_proto, sizeAlloc);
            if (!pointer.isNull())
                sections.push(["protocol conformance", pointer, Memory.readULong(sizeAlloc)]);
            for (let section of sections) {
                for (let i = 0; i < section[2]; i += section[0] === "types" ? 8 : 16) {
                    let nominalType = null;
                    let canonicalType = null;
                    if (section[0] === "types") {
                        let record = new types.TargetTypeMetadataRecord(section[1].add(i));

                        try {
                            nominalType = record.getNominalTypeDescriptor();
                        } catch (e) {
                        }
                        try {
                            canonicalType = record.getCanonicalTypeMetadata(this._api);
                        } catch (e) {
                        }
                    } else {
                        let record = new types.TargetProtocolConformanceRecord(section[1].add(i));
                        try {
                            canonicalType = record.getCanonicalTypeMetadata(this._api);
                        } catch(e) {
                        }
                    }

                    if (nominalType === null && canonicalType !== null) {
                        do {
                            nominalType = canonicalType.getNominalTypeDescriptor();
                            if (nominalType !== null)
                                break;
                            if (canonicalType.kind !== MetadataKind.Class)
                                break;
                            let clsType = new types.TargetClassMetadata(canonicalType._ptr);
                            if (clsType.isTypeMetadata() && clsType.isArtificialSubclass() && canonicalType._ptr !== clsType.superClass._ptr) {
                                canonicalType = clsType.superClass;
                            } else
                                break;
                        } while (true);
                    }
                    if (!nominalType)
                        //console.log("no nominal type");
                        ;
                    else
                        names.push(nominalType.name);
                }
            }
        }
        return names;
    },

    get _api() {
        if (_api !== null)
            return _api;
        if (!this.available)
            return null;

        const temporaryApi = {};
        const pending = [
            {
                module: "libsystem_malloc.dylib",
                functions: {
                    "free": ['void', ['pointer']],
                }
            },
            {
                module: "libmacho.dylib",
                functions: {
                    "getsectiondata": ['pointer', ['pointer', 'pointer', 'pointer', 'pointer']],
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
                    "swift_getTypeByName": ['pointer', ['pointer', size_t]], // const Metadata * swift_getTypeByName(const char *typeName, size_t typeNameLength)

                    "_T0s16_DebuggerSupportO20stringForPrintObjectSSypFZ": ['void', OpaqueExistentialContainer]
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
    },
};
