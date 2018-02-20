"use strict";

/* jshint esnext: true, evil: true */

const types = require('./types');
const mangling = require('./mangling');

let size_t = Process.pointerSize === 8 ? 'uint64' : Process.pointerSize === 4 ? 'uint32' : "unsupported platform";

function strlen(pointer) {
    let i;
    for (i = 0; Memory.readU8(pointer.add(i)) !== 0; i++) {
    }
    return i;
}

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

function Type(nominalType, canonicalType) {
    this.nominalType = nominalType;
    if (!canonicalType & !this.hasGenericRequirements()) {
        return this.withGenericParams();
    }
    if (!nominalType && canonicalType) {
        this.nominalType = canonicalType.getNominalTypeDescriptor();
        if (canonicalType.kind === types.MetadataKind.Class) {
            let clsType = canonicalType;
            while (this.nominalType === null && clsType.isTypeMetadata() && clsType.isArtificialSubclass() && clsType.superClass !== null) {
                clsType = clsType.superClass;
                this.nominalType = clsType.getNominalTypeDescriptor();
            }
        }
    }
    this.canonicalType = canonicalType;
}
Type.prototype = {
    hasGenericRequirements() {
        if (!this.nominalType || this.canonicalType)
            return false;
        return this.nominalType.genericParams.hasGenericRequirements();
    },
    withGenericParams(...params) {
        if (!this.nominalType)
            throw Error("not a generic type");
        if (params.length != this.nominalType.genericParams.numGenericRequirements)
            throw Error("wrong number of generic parameters");

        for (let param of params) {
            if (param.hasGenericRequirements())
                throw Error("generic type parameter needs all own type parameters filled!");
        }
        let canonical = this.nominalType.accessFunction.apply(null, params.map(t => t.canonicalType));
        return new Type(this.nominalType, new types.TargetMetadata(canonical));
    },
    enumCases() {
        if (!this.nominalType || !this.canonicalType)
            throw Error("information not available");
        if (this.canonicalType.kind != types.MetadataKind.Enum)
            throw Error("not an enum type");
        let info = this.nominalType.enum_;
        let count = info.getNumCases();
        let payloadCount = info.getNumPayloadCases();
        let cases = [];
        let names = info.caseNames;
        let caseTypeAccessor = new NativeFunction(info.getCaseTypes, 'pointer', ['pointer']);
        let caseTypes = caseTypeAccessor(this.canonicalType._ptr);
        for (let i = 0; i < count; i++) {
            let type = null;
            let typeFlags = 0;
            if (i < payloadCount) {
                type = Memory.readPointer(caseTypes.add(i * Process.pointerSize));
                typeFlags = type.and(types.FieldTypeFlags.typeMask);
                type = new types.TargetMetadata(type.and(~types.FieldTypeFlags.typeMask));
            }
            cases.push({
                name: Memory.readUtf8String(names),
                type: type === null ? null : new Type(null, type),
                indirect: (typeFlags & types.FieldTypeFlags.Indirect) === types.FieldTypeFlags.Indirect,
                weak: (typeFlags & types.FieldTypeFlags.Weak) === types.FieldTypeFlags.Weak,
            });
            names = names.add(strlen(names) + 1);
        }
        return cases;
    },
    tupleElements() {
        if (!this.canonicalType)
            throw Error("information not available");
        if (this.canonicalType.kind != types.MetadataKind.Tuple)
            throw Error("not a tuple type");
        let labels = this.canonicalType.labels;
        if (labels.isNull())
            labels = null;
        else
            labels = Memory.readUtf8String(labels).split(" ");
        let infos = [];
        let elements = this.canonicalType.elements;
        for (let i = 0; i < this.canonicalType.numElements; i++) {
            infos.push({
                label: labels && labels[i] ? labels[i] : null,
                type: new Type(null, elements[i].type),
                offset: elements[i].offset,
            });
        }
        return infos;
    },
    fields() {
        if (this.nominalType === null)
            return [];
        if (this.canonicalType === null)
            throw Error("fields can only be accessed for fully concrete types");

        let fields = [];
        let info;
        switch (this.nominalType.getKind()) {
            case types.NominalTypeKind.Class:
                info = this.nominalType.clas;
                break;
            case types.NominalTypeKind.Struct:
                info = this.nominalType.struct;
                break;
            default:
                return fields;
        }
        if (!info.hasFieldOffsetVector())
            throw Error("fields without offset vector not implemented");


        let fieldTypeAccessor = new NativeFunction(info.getFieldTypes, 'pointer', ['pointer']);
        let fieldTypes = fieldTypeAccessor(this.canonicalType._ptr);

        let fieldName = info.fieldNames;
        let fieldOffsets = this.canonicalType._ptr.add(info.fieldOffsetVectorOffset * Process.pointerSize);
        for (let i = 0; i < info.numFields; i++) {
            let type = Memory.readPointer(fieldTypes.add(i * Process.pointerSize));
            let typeFlags = type.and(types.FieldTypeFlags.typeMask);
            type = new types.TargetMetadata(type.and(~types.FieldTypeFlags.typeMask));

            fields.push({
                name: Memory.readUtf8String(fieldName),
                offset: Memory.readPointer(fieldOffsets.add(i * Process.pointerSize)),
                type: new Type(null, type),
                indirect: (typeFlags & types.FieldTypeFlags.Indirect) === types.FieldTypeFlags.Indirect,
                weak: (typeFlags & types.FieldTypeFlags.Weak) === types.FieldTypeFlags.Weak,
            });
            fieldName = fieldName.add(strlen(fieldName) + 1);
        }
        return fields;
    },

    toString() {
        let canon = this.canonicalType ? this.canonicalType.toString() : "null";
        let nomin = this.nominalType ? this.nominalType.toString() : "null";
        return "Swift.Type {\n\
    canonicalType: " + canon + "\n\
    nominalType: " + nomin + "\n\
}";
    },
};


function findAllTypes(api) {
    let sizeAlloc = Memory.alloc(8);
    let found = [];
    const __TEXT = Memory.allocUtf8String("__TEXT");
    const __swift2_types = Memory.allocUtf8String("__swift2_types");
    const __swift2_proto = Memory.allocUtf8String("__swift2_proto");

    const recordSizes = {
        'types': 8,
        'protocol conformance': 16,
    };

    for (let mod of Process.enumerateModulesSync()) {
        for (let [section, what] of [[__swift2_types, "types"], [__swift2_proto, "protocol conformance"]]) {
            // we don't have to use the name _mh_execute_header to refer to the mach-o header -- it's the module header
            let pointer = api.getsectiondata(mod.base, __TEXT, section, sizeAlloc);
            if (pointer.isNull())
                continue;

            let sectionSize = Memory.readULong(sizeAlloc);
            for (let i = 0; i < sectionSize; i += recordSizes[what]) {
                let nominalType = null;
                let record;
                if (what === "types") {
                    record = new types.TargetTypeMetadataRecord(pointer.add(i));

                    if (record.getTypeKind() == types.TypeMetadataRecordKind.UniqueNominalTypeDescriptor)
                        nominalType = record.getNominalTypeDescriptor();
                } else {
                    record = new types.TargetProtocolConformanceRecord(pointer.add(i));
                }
                let canonicalType = record.getCanonicalTypeMetadata(api);

                if (nominalType || canonicalType)
                    found.push(new Type(nominalType, canonicalType));
            }
        }
    }
    return found;
}

module.exports = {

    get available() {
        return Module.findBaseAddress("libswiftCore.dylib") !== null;
    },

    isSwiftFunction(func) {
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
            throw Error("function name '" + name + "' is not a mangled Swift function");

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
        let typesByName = new Map();
        for (let type of findAllTypes(this._api)) {
            if (type.nominalType !== null) {
                let name = this.demangle(type.nominalType.mangledName);
                typesByName.set(name, type);
            }
        }
        this._typesByName = typesByName;
        return Array.from(typesByName.keys());
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
