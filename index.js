"use strict";

/* jshint esnext: true, evil: true */

let size_t = Process.pointerSize == 8 ? 'uint64' : Process.pointerSize == 4 ? 'uint32' : "unsupported platform";


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


const TypeMetadataRecordKind = {
    Universal: 0,
    UniqueDirectType: 1,
    NonuniqueDirectType: 2,
    UniqueIndirectClass : 3,
    UniqueNominalTypeDescriptor: 4,
    UniqueDirectClass: 0xF,
};


function RelativeDirectPointerIntPair(ptr) {
    let val = Memory.readS32(ptr);
    let offset = val & (~0x3);
    let intVal = val & 0x3;
    return {
        pointer: ptr.add(val & (~0x3)),
        intVal: val & 0x3,
    };
}

function TargetRelativeDirectPointerRuntime(ptr) {
    let offset = Memory.readS32(ptr);
    return ptr.add(offset);
}
function TargetNominalTypeDescriptor(ptr) {
    this._ptr = ptr;
}
TargetNominalTypeDescriptor.prototype = {
    // offset 0
    get name() {
        return Memory.readCString(TargetRelativeDirectPointerRuntime(this._ptr));
    },
    // offset 4
    get clas() {
        let ptr = this._ptr.add(4);
        return {
            // offset 0
            get numFields() {
                return Memory.readU32(ptr.add(0));
            },
            // offset 4
            get fieldOffsetVectorOffset() {
                return Memory.readU32(ptr.add(4));
            },
            // offset 8
            // doubly-null-terminated list of strings
            get fieldNames() {
                return TargetRelativeDirectPointerRuntime(ptr.add(8));
            },
            // offset 12
            get getFieldTypes() {
                return TargetRelativeDirectPointerRuntime(ptr.add(12));
            },
            hasFieldOffsetVector() {
                return this.fieldOffsetVectorOffset != 0;
            },
        };
    },

    // offset 4
    get struct() {
        return this.clas;
    },

    // offset 4
    get enum_() {
        let ptr = this._ptr.add(4);
        return {
            // offset 0
            get numPayloadCasesAndPayloadSizeOffset() {
                return Memory.readU32(ptr.add(0));
            },
            // offset 4
            get numEmptyCases() {
                return Memory.readU32(ptr.add(4));
            },
            // offset 8
            // doubly-null-terminated list of strings
            get caseNames() {
                return TargetRelativeDirectPointerRuntime(ptr.add(8));
            },
            // offset 12
            get getCaseTypes() {
                return TargetRelativeDirectPointerRuntime(ptr.add(12));
            },

            getNumPayloadCases() {
                return this.numPayloadCasesAndPayloadSizeOffset & 0x00FFFFFF;
            },
            getNumCases() {
                return this.getNumPayloadCases() + this.numEmptyCases;
            },
            getPayloadSizeOffset() {
                return ((this.numPayloadCasesAndPayloadSizeOffset & 0xFF000000) >> 24);
            },
            hasPayloadSizeOffset() {
                return this.getPayloadSizeOffset() != 0;
            }
        };
    },


    // offset 16
    get genericMetadataPatternAndKind() {
        return RelativeDirectPointerIntPair(this._ptr.add(16));
    },

    // offset 20
    get accessFunction() {
        return RelativeDirectPointer(this._ptr.add(20)); // the type of this function depends on the generic requirements of this type
    },

    getGenericMetadataPattern() {
        return this.genericMetadataPatternAndKind.pointer;
    },

    getKind() {
        return this.genericMetadataPatternAndKind.intVal;
    },

    offsetToNameOffset() {
        return 0;
    },

    // offset 24
    get GenericParams() {
        let ptr = this._ptr.add(24);
        const GenericParameterDescriptorFlags = {
            HasParent: 1,
            HasGenericParent: 2,
        };
        return {
            // offset 0
            get offset() {
                return Memory.readU32(ptr.add(0));
            },
            // offset 4
            get numGenericRequirements() {
                return Memory.readU32(ptr.add(4));
            },
            // offset 8
            get numPrimaryParams() {
                return Memory.readU32(ptr.add(8));
            },
            // offset 12
            get flags() {
                return Memory.readU32(ptr.add(12));
            },

            hasGenericRequirements() {
                return this.numPrimaryParams > 0;
            },

            isGeneric() {
                return this.hasGenericRequirements() || (this.flags & GenericParameterDescriptorFlags.HasGenericParent) != 0;
            },
        };
    },
};

function TargetTypeMetadataRecord(record) {
    this._record = record;
}
TargetTypeMetadataRecord.prototype = {
    get _directType() {
        return TargetRelativeDirectPointerRuntime(this._record);
    },
    get _typeDescriptor() {
        return TargetRelativeDirectPointerRuntime(this._record);
    },

    get _flags() {
        return Memory.readUInt(this._record.add(4));
    },

    getTypeKind() {
        const TypeKindMask = 0x0000000F;
        const TypeKindShift = 0;
        return (this._flags & TypeKindMask) >>> TypeKindShift; // see TypeMetadataRecordKind
    },

    getDirectType() {
        switch(this.getTypeKind()) {
            case TypeMetadataRecordKind.Universal:
                return null;

            case TypeMetadataRecordKind.UniqueDirectType:
            case TypeMetadataRecordKind.NonuniqueDirectType:
            case TypeMetadataRecordKind.UniqueDirectClass:
                break;

            case TypeMetadataRecordKind.UniqueIndirectClass:
            case TypeMetadataRecordKind.UniqueNominalTypeDescriptor:
                throw Error("not direct type metadata");

            default:
                throw Error("invalid type kind");
        }

        return this._directType;
    },

    getNominalTypeDescriptor() {
        switch (this.getTypeKind()) {
            case TypeMetadataRecordKind.Universal:
                return null;

            case TypeMetadataRecordKind.UniqueNominalTypeDescriptor:
                break;

            case TypeMetadataRecordKind.UniqueDirectClass:
            case TypeMetadataRecordKind.UniqueIndirectClass:
            case TypeMetadataRecordKind.UniqueDirectType:
            case TypeMetadataRecordKind.NonuniqueDirectType:
                throw Error("not generic metadata pattern");

            default:
                throw Error("invalid type kind");
        }

        return new TargetNominalTypeDescriptor(this._typeDescriptor);
    },

    getCanonicalTypeMetadata(api) { // returns a Metadata* for non-generic types
        switch (this.getTypeKind()) {
            case TypeMetadataRecordKind.UniqueDirectType:
                return this.getDirectType();
            case TypeMetadataRecordKind.NonuniqueDirectType:
                return api.swift_getForeignTypeMetadata(this.getDirectType());
            case TypeMetadataRecordKind.UniqueDirectClass:
                let directType = this.getDirectType();
                if (directType)
                    return api.swift_getObjCClassMetadata(directType);
                return null;
            default:
                return null;
        }
    },
}

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

    getClassMetadata(name) {
        /*// that function only supports classes:
        let cStr = Memory.allocUtf8String(name);
        let type = this._api.swift_getTypeByName(name, name.length);
        return type;*/
        // TODO: manually parse type data
        let sizeAlloc = Memory.alloc(8);
        let types = [];
        for (let mod of Process.enumerateModulesSync()) {
            let sections = [];
            const __TEXT = Memory.allocUtf8String("__TEXT");
            const __swift2_types = Memory.allocUtf8String("__swift2_types");
            const __swift2_proto = Memory.allocUtf8String("__swift2_proto");
            // we don't have to use the name _mh_execute_header to refer to the mach-o header -- it's the module header
            let ptr = this._api.getsectiondata(mod.base, __TEXT, __swift2_types, sizeAlloc);
            if (!ptr.isNull())
                sections.push(["types", ptr, Memory.readULong(sizeAlloc)]);
            ptr = this._api.getsectiondata(mod.base, __TEXT, __swift2_proto, sizeAlloc);
            if (!ptr.isNull())
                sections.push(["protocol conformance", ptr, Memory.readULong(sizeAlloc)]);
            for (let section of sections) {
                for (let i = 0; i < section[2]; i += 8) {
                    let metadata;
                    if (section[0] == "types") {
                        let record = new TargetTypeMetadataRecord(section[1].add(i));
                        metadata = record.getCanonicalTypeMetadata(this._api);

                        if (metadata === null) {
                            metadata = record.getNominalTypeDescriptor().name;
                            //  TODO
                        }
                    } else {
                        metadata = null;
                        // TODO
                    }
                    if (metadata !== null)
                        types.push(metadata);
                }
            }
        }
        return types;
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
