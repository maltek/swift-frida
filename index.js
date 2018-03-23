"use strict";

/* jshint esnext: true, evil: true */

const types = require('./types');
const mangling = require('./mangling');
const swiftValue = require('./swift-value.js');
let Swift;

let size_t = Process.pointerSize === 8 ? 'uint64' : Process.pointerSize === 4 ? 'uint32' : "unsupported platform";

function strlen(pointer) {
    let i;
    for (i = 0; Memory.readU8(pointer.add(i)) !== 0; i++) {
    }
    return i;
}

let _api = null;

function toString(type, pointer) {
    /*
     * built by disassembling the code for this snippet:
     *
        var str = String()
        dump(x, to: &str)
        let arr : [CChar] = str.cString(using: String.Encoding.utf8)!
        let ptr = UnsafePointer<CChar>(arr)
        strlen(ptr)
     */
}

// reads a Swift `String` from a NativePointer or an args-like array of NativePointers
function readSwiftString(data) {
    /*
     * built by disassembling the code for this snippet:
     *
        let arr = x.cString(using: String.Encoding.utf8)!
        let ptr = UnsafePointer<CChar>(arr)
    */
    let encoding = Memory.readPointer(_api._T0SS10FoundationE8EncodingV4utf8ACfau());
    let stringType = Swift._typesByName.get("Swift.String");
    let witnessTableStringProtocol = _api._T0SSs14StringProtocolsWP;

    let toCString = _api._T0s14StringProtocolP10FoundationsAARzSS5IndexVADRtzlE01cA0Says4Int8VGSgSSACE8EncodingV5using_tF;
    let array = toCString(encoding, stringType.canonicalType._ptr, witnessTableStringProtocol);
    let pointer = array.add(8 + 3 * Process.pointerSize); // TODO: take this offset from type metadata
    let str = Memory.readUtf8String(pointer);
    _api.swift_bridgeObjectRelease(array);

    return str;

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
                                   ];

const typesByCanonical = new Map();

function Type(nominalType, canonicalType, name, accessFunction) {
    if (canonicalType && typesByCanonical.has(canonicalType._ptr.toString())) {
        let unique = typesByCanonical.get(canonicalType._ptr.toString());
        if (name && !unique.fixedName)
            unique.fixedName = name;
        return unique;
    }

    if (accessFunction) {
        if (nominalType || canonicalType || !name)
            throw Error("type access function must only be provided if the type is not known");
        this.fixedName = name;
        this.accessFunction = accessFunction;
    }

    this.nominalType = nominalType;
    if (!nominalType && canonicalType) {
        this.nominalType = canonicalType.getNominalTypeDescriptor();
        if (canonicalType.kind === "Class") {
            let clsType = canonicalType;
            while (this.nominalType === null && clsType.isTypeMetadata() && clsType.isArtificialSubclass() && clsType.superClass !== null) {
                clsType = clsType.superClass;
                this.nominalType = clsType.getNominalTypeDescriptor();
            }
        }
    }
    this.canonicalType = canonicalType;
    this.kind = canonicalType ? canonicalType.kind : accessFunction ? "Unknown" : null;

    if ((this.nominalType && !canonicalType))
        accessFunction = this.nominalType.accessFunction;
    if (accessFunction) {
        this.withGenericParams = function withGenericParams(...params) {
            // when there is a generic parent, we don't know the number of generic parameters
            if (this.nominalType && !this.nominalType.genericParams.flags.HasGenericParent &&
                    params.length != this.nominalType.genericParams.numGenericRequirements) {
                throw Error("wrong number of generic parameters");
            }

            let args = [];
            for (let param of params) {
                if (param.isGeneric() || !param.canonicalType)
                    throw Error("generic type parameter needs all own type parameters filled!");
                args.push('pointer');
            }
            let accessFunc = new NativeFunction(accessFunction, 'pointer', args);
            let canonical = accessFunc.apply(null, params.map(t => t.canonicalType._ptr));
            return new Type(this.nominalType, new types.TargetMetadata(canonical));
        };
    }
    if (this.nominalType && canonicalType) {
        if (this.kind === "Enum") {
            this.enumCases = function enumCases() {
                let info = this.nominalType.enum_;
                let count = info.getNumCases();
                let payloadCount = info.getNumPayloadCases();
                let cases = [];
                let names = info.caseNames;
                let caseTypeAccessor = new NativeFunction(info.getCaseTypes, 'pointer', ['pointer']);
                let caseTypes = caseTypeAccessor(canonicalType._ptr);
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
            };
        }
        if (["Class", "Struct"].indexOf(this.nominalType.getKind()) !== -1 && canonicalType) {
            this.fields = function fields() {
                let results = [];
                let hierarchy = [canonicalType];
                while (hierarchy[hierarchy.length - 1].superClass) {
                    hierarchy.push(hierarchy[hierarchy.length - 1].superClass);
                }
                for (let i = hierarchy.length; i--;) {
                    let canon = hierarchy[i];
                    let nomin = (["Class", "Struct"].indexOf(canon.kind) != -1) ? canon.getNominalTypeDescriptor() : null;
                    if (!nomin)
                        continue;
                    let info = (nomin.getKind() === "Class") ? nomin.clas : nomin.struct;
                    if (!info.hasFieldOffsetVector())
                        throw Error("fields without offset vector not implemented");

                    let fieldTypeAccessor = new NativeFunction(info.getFieldTypes, 'pointer', ['pointer']);
                    let fieldTypes = fieldTypeAccessor(canon._ptr);

                    let fieldName = info.fieldNames;
                    let fieldOffsets = canon._ptr.add(info.fieldOffsetVectorOffset * Process.pointerSize);
                    for (let j = 0; j < info.numFields; j++) {
                        let type = Memory.readPointer(fieldTypes.add(j * Process.pointerSize));
                        let typeFlags = type.and(types.FieldTypeFlags.typeMask);
                        type = new types.TargetMetadata(type.and(~types.FieldTypeFlags.typeMask));

                        results.push({
                            name: Memory.readUtf8String(fieldName),
                            offset: Memory.readPointer(fieldOffsets.add(j * Process.pointerSize)),
                            type: new Type(null, type, "?Unknown type of " +  this.toString()),
                            indirect: (typeFlags & types.FieldTypeFlags.Indirect) === types.FieldTypeFlags.Indirect,
                            weak: (typeFlags & types.FieldTypeFlags.Weak) === types.FieldTypeFlags.Weak,
                        });
                        fieldName = fieldName.add(strlen(fieldName) + 1);
                    }
                }
                return results;
            };
        }
    }
    if (this.kind === "Tuple") {
        this.tupleElements = function tupleElements() {
            let labels = canonicalType.labels;
            if (labels.isNull())
                labels = null;
            else
                labels = Memory.readUtf8String(labels).split(" ");
            let infos = [];
            let elements = canonicalType.elements;
            for (let i = 0; i < canonicalType.numElements; i++) {
                infos.push({
                    label: labels && labels[i] ? labels[i] : null,
                    type: new Type(null, elements[i].type),
                    offset: elements[i].offset,
                });
            }
            return infos;
        };
    }
    if (this.kind === "Function") {
        this.returnType = function returnType() {
            return new Type(null, canonicalType.resultType);
        };
        this.functionFlags = function functionFlags() {
            return canonicalType.flags;
        };
        this.getArguments = function getArguments() {
            return canonicalType.getArguments().map(arg => {
                return {
                    inout: arg.inout,
                    type: new Type(null, arg.type),
                };
            });
        };
    }
    if (this.kind == "Opaque") {
        if (!name)
            throw Error("a name is required when creating Opaque types");
        this.fixedName = name;
    }

    if (canonicalType) {
        this.getGenericParams = function getGenericParams() {
            if (!canonicalType.getGenericArgs)
                throw Error("generic arguments for this kind of type not implemented");
            return canonicalType.getGenericArgs().map(t => t === null ? null : new Type(null, t));
        };
    }
    if (this.kind === "ObjCClassWrapper") {
        this.getObjCObject = function getObjCObject() {
            return ObjC.Object(canonicalType.class_);
        };
    }

    if (!this.isGeneric()) {
        if (!canonicalType) {
            return this.withGenericParams();
        } else {
            let func = swiftValue.makeSwiftValue(this);
            Object.assign(func, this);
            Reflect.setPrototypeOf(func, Type.prototype);
            typesByCanonical.set(this.canonicalType._ptr.toString(), func);
            return func;
        }
    }
}
Type.prototype = {
    constructor: Type,
    isGeneric() {
        if (this.accessFunction)
            return true;

        if (!this.nominalType || this.canonicalType)
            return false;
        return this.nominalType.genericParams.isGeneric();
    },

    toString() {
        if (this.canonicalType) {
            let [pointer, len] = Swift._api.swift_getTypeName(this.canonicalType._ptr, /* qualified? */ 1);
            let str = Memory.readUtf8String(pointer, len.toInt32());
            if (str === "<<< invalid type >>>" && this.fixedName) {
                return this.fixedName;
            }
            return str;
        }

        if (this.nominalType) {
            let name = Swift.demangle(this.nominalType.mangledName);
            if (this.nominalType.genericParams.isGeneric()) {
                let params = [];
                if (this.canonicalType) {
                    params = this.getGenericParams().map(arg => arg.toString());
                } else {
                    if (this.nominalType.genericParams.flags.HasGenericParent) {
                        params.push("[inherited generic parameters]");
                    }
                    let cnt = this.nominalType.genericParams.numPrimaryParams;
                    for (let i = 0; i < cnt; i++) {
                        params.push("_T" + i);
                    }
                }
                name +=  "<" + params.join(", ") + ">";
            }
            return name;
        }

        if (this.fixedName)
            return this.fixedName;

        throw Error(`cannot get string representation for type without nominal or canonical type information`);
    },
};


function findAllTypes(api) {
    let sizeAlloc = Memory.alloc(8);
    const __TEXT = Memory.allocUtf8String("__TEXT");

    const sectionNames = [Memory.allocUtf8String("__swift2_types"), Memory.allocUtf8String("__swift2_proto")];
    const recordSizes = [8, 16];

    let typesByName = new Map();
    for (let mod of Process.enumerateModulesSync()) {
        for (let section = 0; section < sectionNames.length; section++) {
            // we don't have to use the name _mh_execute_header to refer to the mach-o header -- it's the module header
            let pointer = api.getsectiondata(mod.base, __TEXT, sectionNames[section], sizeAlloc);
            if (pointer.isNull())
                continue;

            let sectionSize = Memory.readULong(sizeAlloc);
            for (let i = 0; i < sectionSize; i += recordSizes[section]) {
                let record;
                if (section === 0) {
                    record = new types.TargetTypeMetadataRecord(pointer.add(i));
                } else {
                    record = new types.TargetProtocolConformanceRecord(pointer.add(i));
                }
                let nominalType = null;
                if (record.getTypeKind() === types.TypeMetadataRecordKind.UniqueNominalTypeDescriptor)
                    nominalType = record.getNominalTypeDescriptor();

                let canonicalType = record.getCanonicalTypeMetadata(api);

                if (nominalType || canonicalType) {
                    let t = new Type(nominalType, canonicalType);
                    typesByName.set(t.toString(), t);
                } else {
                    console.log("metadata record without nominal or canonical type?! @" + pointer.add(i));
                }
            }
        }

        // TODO: it kind of sucks that we rely on symbol information here.
        // we should see if there is some other way to find the nominal types for generic data types
        const METADATA_PREFIX = "type metadata for ";
        const METADATA_ACCESSOR_PREFIX = "type metadata accessor for ";
        for (let exp of Module.enumerateExportsSync(mod.name)) {
            if (Swift.isSwiftName(exp.name)) {
                let demangled = Swift.demangle(exp.name);
                if (demangled.startsWith(METADATA_PREFIX)) {
                    let name = demangled.substr(METADATA_PREFIX.length);
                    if (!typesByName.get(name)) {
                        // type metadata sometimes can have members at negative indices, so we need to
                        // iterate until we find something that looks like the beginning of a Metadata object
                        // (Sadly, that doesn't work for class metadata with ISA pointers, but it should be no
                        // problem to find ObjC metadata for such classes.)
                        for (let i = 0; i < 2; i++) {
                            let ptr = exp.address.add(Process.pointerSize * i);
                            if (Memory.readPointer(ptr).toString(10) in types.MetadataKind) {
                                typesByName.set(name, new Type(null, new types.TargetMetadata(ptr), name));
                                break;
                            }
                        }
                    }
                } else if (demangled.startsWith(METADATA_ACCESSOR_PREFIX)) {
                    let name = demangled.substr(METADATA_ACCESSOR_PREFIX.length);
                    if (!typesByName.get(name)) {
                        typesByName.set(name, new Type(null, null, name, exp.address));
                    }
                }
            }
        }

    }
    return typesByName;
}

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
        let typesByName = findAllTypes(this._api);

        this._typesByName = typesByName;
        return Array.from(typesByName.values());
    },

    _leakedLabels: [],
    makeTupleType(labels, innerTypes) {
        if (innerTypes.length != labels.length)
            throw Error("labels array and innerTypes array need the same length!");
        let elements = innerTypes.length ? Memory.alloc(Process.pointerSize * innerTypes.length) : ptr(0);
        let labelsStr = Memory.allocUtf8String(labels.join(" ") + " ");
        this._leakedLabels.push(labelsStr); // if the tuple type is new, we must not ever dealllocate this string
        for (let i = 0; i < innerTypes.length; i++) {
            Memory.writePointer(elements.add(i * Process.pointerSize), innerTypes[i].canonicalType._ptr);
        }
        let valueWitnesses = ptr(0);
        let pointer = this._api.swift_getTupleTypeMetadata(innerTypes.length, elements, labelsStr, valueWitnesses);
        return new Type(null, new types.TargetMetadata(pointer));
    },

    makeFunctionType(args, returnType, flags) {
        let data = Memory.alloc(Process.pointerSize * (2 + args.length));

        let writeFlags = ptr(args.length).and(types.TargetFunctionTypeFlags.NumArgumentsMask);
        if (flags && flags.doesThrow)
            writeFlags = writeFlags.or(ptr(types.TargetFunctionTypeFlags.ThrowsMask));
        if (flags && flags.convention)
            writeFlags = writeFlags.or(ptr(flags.convention).shl(types.TargetFunctionTypeFlags.ConventionShift));

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
        return new Type(null, new types.TargetMetadata(pointer));
    },

    // Create a new Type object, from a Metadata*.
    // The name is only used for opaque types (builtins).
    _typeFromCanonical(pointer, name) {
        return new Type(null, new types.TargetMetadata(pointer), name);
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
                // see https://github.com/apple/swift/blob/master/docs/Runtime.md
                module: "libswiftCore.dylib",
                variables: [
                    //"_T0SSs14StringProtocolsWP", // protocol witness table for Swift.String : Swift.StringProtocol in Swift
                ],
                functions: {
                    "swift_bridgeObjectRelease": ['void', ['pointer']],
                    "swift_demangle": ['pointer', ['pointer', size_t, 'pointer', 'pointer', 'int32']],
                    //'swift_allocObject': ['pointer', ['pointer', size_t, size_t]],
                    //'swift_allocBox': [['pointer', 'pointer'], ['pointer']],
                    //'swift_deallocBox': ['void', ['pointer']],
                    'swift_stringFromUTF8InRawMemory': ['void', ['pointer', 'pointer', size_t]],

                    "swift_getTupleTypeMetadata": ['pointer', [size_t, 'pointer', 'pointer', 'pointer']],
                    //"swift_getExistentialMetatypeMetadata": ['pointer', ['pointer']],
                    //"swift_getExistentialTypeMetadata": ['pointer', [size_t, 'pointer', size_t, 'pointer']],
                    //'swift_getGenericMetadata': ['pointer', ['pointer', 'pointer']],
                    "swift_getObjCClassMetadata": ['pointer', ['pointer']],
                    "swift_getFunctionTypeMetadata": ['pointer', ['pointer']],
                    "swift_getForeignTypeMetadata": ['pointer', ['pointer']],
                    "swift_getMetatypeMetadata": ['pointer', ['pointer']],

                    "swift_getEnumCaseSinglePayload": ['int',  ['pointer', 'pointer', 'uint']],
                    "swift_getEnumCaseMultiPayload": ['uint',  ['pointer', 'pointer']],

                    "swift_getTypeName": [['pointer', 'pointer'],  ['pointer', 'uchar']],

                    "_T0s16_DebuggerSupportO20stringForPrintObjectSSypFZ": ['void', OpaqueExistentialContainer],
                    "_T0s4dumpxx_q_z2toSSSg4nameSi6indentSi8maxDepthSi0E5Itemsts16TextOutputStreamR_r0_lF": ['void', ['void', 'void', 'void', 'void', 'void', 'void', 'void']],
                },
            }
        ];
        let remaining = 0;
        pending.forEach(api => {
            const functions = api.functions || {};
            const variables = api.variables || {};
            const optionals = api.optionals || {};

            remaining += Object.keys(functions).length + Object.keys(variables).length;

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
