"use strict";

/* jshint esnext: true, evil: true */

const metadata = require('./metadata');
const types = require('./types');
const mangling = require('./mangling');
const swiftValue = require('./swift-value');
let Swift;
let _api = null;

let _leakedMemory = []; // some runtime functions take pointers that must remain valid forever

let size_t = Process.pointerSize === 8 ? 'uint64' : Process.pointerSize === 4 ? 'uint32' : "unsupported platform";

Swift = module.exports = {

    get available() {
        return Module.findBaseAddress("libswiftCore.dylib") !== null;
    },

    isSwiftName(func) {
        let name = func.name || func;
        return name.startsWith(mangling.MANGLING_PREFIX);
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

    _mangled: new Map(),

    // does not actually mangle the name, only has a lookup table with all names that have been demangled earlier
    get_mangled(name) {
        return this._mangled.get(name);
    },

    demangle(name) {
        if (!Swift.isSwiftName(name))
            throw new Error("function name '" + name + "' is not a mangled Swift function");

        let cStr = Memory.allocUtf8String(name);
        let demangled = this._api.swift_demangle(cStr, name.length, ptr(0), ptr(0), 0);
        let res = Memory.readUtf8String(demangled);
        if ("free" in this._api)
            this._api.free(demangled);

        this._mangled.set(res, name);

        return res;
    },

    _typesByName: null,
    enumerateTypesSync() {
        let typesByName = types.findAllTypes(this._api);

        this._typesByName = typesByName;
        return Array.from(typesByName.values());
    },

    makeTupleType(labels, innerTypes) {
        if (innerTypes.length != labels.length)
            throw new Error("labels array and innerTypes array need the same length!");
        let elements = innerTypes.length ? Memory.alloc(Process.pointerSize * innerTypes.length) : ptr(0);
        let labelsStr = Memory.allocUtf8String(labels.join(" ") + " ");
        for (let i = 0; i < innerTypes.length; i++) {
            Memory.writePointer(elements.add(i * Process.pointerSize), innerTypes[i].canonicalType._ptr);
        }
        let valueWitnesses = ptr(0);
        let pointer = this._api.swift_getTupleTypeMetadata(innerTypes.length, elements, labelsStr, valueWitnesses);
        let canonical = new metadata.TargetMetadata(pointer);

        if (canonical.labels.toString === labelsStr.toString())
            _leakedMemory.push(labelsStr); // if the tuple type is new, we must not ever dealllocate this string

        return new types.Type(null, canonical);
    },

    makeFunctionType(args, returnType, flags) {
        let data = Memory.alloc(Process.pointerSize * (2 + args.length));

        let writeFlags = ptr(args.length).and(metadata.TargetFunctionTypeFlags.NumArgumentsMask);
        if (flags && flags.doesThrow)
            writeFlags = writeFlags.or(ptr(metadata.TargetFunctionTypeFlags.ThrowsMask));
        if (flags && flags.convention)
            writeFlags = writeFlags.or(ptr(flags.convention).shl(metadata.TargetFunctionTypeFlags.ConventionShift));

        Memory.writePointer(data, writeFlags);

        for (let i = 0; i < args.length; i++) {
            let val;
            if (args[i] instanceof Type)
                val = args[i].canonicalType._ptr;
            else {
                val = args[i].type.canonicalType._ptr;
                if (args[i].inout)
                    val = val.or(1);
            }
            Memory.writePointer(data.add((i + 1) * Process.pointerSize), val);
        }
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
                },
                // optionals are functions/variables that might not be available
                optionals: {
                    "free": "leaks don't break functionality",
                }
            },
            {
                module: "libmacho.dylib",
                functions: {
                    "getsectiondata": ['pointer', ['pointer', 'pointer', 'pointer', 'pointer']],
                }
            },
            {
                module: "libswiftFoundation.dylib",
                functions: {
                    "_T0SS10FoundationE8EncodingV4utf8ACfau": ['pointer', []],
                    "_T0s14StringProtocolP10FoundationsAARzSS5IndexVADRtzlE01cA0Says4Int8VGSgSSACE8EncodingV5using_tF": ['pointer', ['pointer', 'pointer', 'pointer']],
                }
            },
            {
                module: "CoreFoundation",
                functions: {
                    "CFGetRetainCount": ['long', ['pointer']],
                }
            },
            {
                module: "Foundation",
                functions: {
                    'objc_storeStrong': ['void', ['pointer', 'pointer']],
                }
            },
            {
                // see https://github.com/apple/swift/blob/master/docs/Runtime.md
                module: "libswiftCore.dylib",
                variables: new Set([
                    "_T0SSs14StringProtocolsWP", // protocol witness table for Swift.String : Swift.StringProtocol in Swift
                    "_T0SSs16TextOutputStreamsWP", // protocol witness table for Swift.String : Swift.TextOutputStream in Swift
                    "_T0s19_emptyStringStorages6UInt32Vv", // Swift._emptyStringStorage
                    "_swift_release", // pointer to _swift_release_
                ]),
                functions: {
                    "swift_demangle": ['pointer', ['pointer', size_t, 'pointer', 'pointer', 'int32']],

                    'swift_unknownRetain': ['void', ['pointer']],
                    'swift_unknownRelease': ['void', ['pointer']],
                    'swift_bridgeObjectRelease': ['void', ['pointer']],
                    'swift_weakLoadStrong': ['pointer', ['pointer']],
                    'swift_weakAssign': ['void', ['pointer', 'pointer']],
                    'swift_release': ['void', ['pointer']],
                    'swift_retain': ['void', ['pointer']],

                    //'swift_allocObject': ['pointer', ['pointer', size_t, size_t]],
                    //'swift_allocBox': [['pointer', 'pointer'], ['pointer']],
                    //'swift_deallocBox': ['void', ['pointer']],
                    'swift_projectBox': ['pointer', ['pointer']],
                    'swift_stringFromUTF8InRawMemory': ['void', ['pointer', 'pointer', size_t]],

                    "swift_getTupleTypeMetadata": ['pointer', [size_t, 'pointer', 'pointer', 'pointer']],
                    "swift_getExistentialMetatypeMetadata": ['pointer', ['pointer']],
                    "swift_getExistentialTypeMetadata": ['pointer', ['int8', 'pointer', size_t, 'pointer']],
                    //'swift_getGenericMetadata': ['pointer', ['pointer', 'pointer']],
                    "swift_getObjCClassMetadata": ['pointer', ['pointer']],
                    "swift_getFunctionTypeMetadata": ['pointer', ['pointer']],
                    "swift_getForeignTypeMetadata": ['pointer', ['pointer']],
                    "swift_getMetatypeMetadata": ['pointer', ['pointer']],

                    "swift_getEnumCaseSinglePayload": ['int',  ['pointer', 'pointer', 'uint']],
                    "swift_getEnumCaseMultiPayload": ['uint',  ['pointer', 'pointer']],

                    'swift_conformsToProtocol': ['pointer', ['pointer', 'pointer']],
                    'swift_dynamicCast': ['bool', ['pointer', 'pointer', 'pointer', 'pointer', size_t]],
                    "swift_getDynamicType": ['pointer', ['pointer', 'pointer', 'int8']],

                    "swift_getTypeByName": ['pointer', ['pointer', size_t]],
                    "swift_getTypeName": [['pointer', 'pointer'],  ['pointer', 'uchar']],

                    "_T0s4dumpxx_q_z2toSSSg4nameSi6indentSi8maxDepthSi0E5Itemsts16TextOutputStreamR_r0_lF": [[['pointer', 'pointer', 'pointer'], 'pointer'], ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'int', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer']],

                },
            }
        ];
        pending.forEach(api => {
            const functions = api.functions || {};
            const variables = api.variables || new Set();
            const optionals = api.optionals || {};

            const exportByName = Module
            .enumerateExportsSync(api.module)
            .reduce((result, exp) => {
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
                        temporaryApi[name] = new NativeFunction(exp.address, signature[0], signature[1], signature[2]);
                    }
                } else if(!(name in optionals)) {
                    throw new Error(`missing function '${name}' in module '${api.module}`);
                }
            });

            variables.forEach(function (name) {
                const exp = exportByName[name];
                if (exp !== undefined && exp.type === 'variable') {
                    temporaryApi[name] = exp.address;
                } else if(!(name in optionals)) {
                    throw new Error(`missing variable '${name}' in module '${api.module}`);
                }
            });
        });


        _api = temporaryApi;
        return _api;
    },
};
