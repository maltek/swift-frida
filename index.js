"use strict";

/* jshint esnext: true, evil: true */

const types = require('./types');
const mangling = require('./mangling');
const swiftValue = require('./swift-value.js');
let Swift;

let _leakedMemory = []; // some runtime functions take pointers that must remain valid forever

let size_t = Process.pointerSize === 8 ? 'uint64' : Process.pointerSize === 4 ? 'uint32' : "unsupported platform";

function strlen(pointer) {
    let i;
    for (i = 0; Memory.readU8(pointer.add(i)) !== 0; i++) {
    }
    return i;
}

let _api = null;

const typesByCanonical = new Map();
const protocolTypes = new Map();
function getOrMakeProtocolType(proto) {
    let existing = protocolTypes.get(proto._ptr.toString());
    if (existing) {
        return existing;
    }

    let arr = Memory.alloc(Process.pointerSize);
    Memory.writePointer(arr, proto._ptr);

    let canonical = _api.swift_getExistentialTypeMetadata(types.ProtocolClassConstraint.Any,
        /*superClass*/ptr(0), /*numProtocols*/ 1, arr);

    // TODO: only leak this, if a new canonical type was created
    _leakedMemory.push(arr);

    let name = Swift.isSwiftName(proto.name) ? Swift.demangle(proto.name) : proto.name;
    let type = new Type(null, new types.TargetMetadata(canonical), name);
    protocolTypes.set(proto._ptr.toString(), type);
    return type;
}

function Type(nominalType, canonicalType, name, accessFunction) {
    if (canonicalType && typesByCanonical.has(canonicalType._ptr.toString())) {
        let unique = typesByCanonical.get(canonicalType._ptr.toString());
        if (name && !unique.fixedName)
            unique.fixedName = name;
        return unique;
    }

    if (accessFunction) {
        if (nominalType || canonicalType || !name)
            throw new Error("type access function must only be provided if the type is not known");
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

    if (canonicalType && ((canonicalType.kind === "Class" && canonicalType.isTypeMetadata() && !canonicalType.flags.UsesSwift1Refcounting) ||
            canonicalType.kind === "ObjCClassWrapper")) {
        this.toJS = function(pointer) { return ObjC.Object(Memory.readPointer(pointer)); };
        this.fromJS = function (address, value) { _api.objc_storeStrong(address, value); return true; };
        this.getSize = function getSize() { return Process.pointerSize; };
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
                throw new Error("wrong number of generic parameters");
            }

            let args = [];
            let names = [];
            for (let param of params) {
                if (param.isGeneric() || !param.canonicalType)
                    throw new Error("generic type parameter needs all own type parameters filled!");
                args.push('pointer');
                names.push(param.toString());
            }
            let name = this.toString();
            if (names.length !== 0)
                name += "<" + names.join(", ") + ">";
            let accessFunc = new NativeFunction(accessFunction, 'pointer', args);
            let canonical = accessFunc.apply(null, params.map(t => t.canonicalType._ptr));
            return new Type(this.nominalType, new types.TargetMetadata(canonical), name);
        };
    }
    if (this.nominalType && canonicalType && (this.kind === "Enum" || this.kind === "Optional")) {
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
                    tag: i - payloadCount,
                    name: names === null ? null : Memory.readUtf8String(names),
                    type: type === null ? null : new Type(null, type),
                    indirect: (typeFlags & types.FieldTypeFlags.Indirect) === types.FieldTypeFlags.Indirect,
                    weak: (typeFlags & types.FieldTypeFlags.Weak) === types.FieldTypeFlags.Weak,
                });
                names = names === null ? null : names.add(strlen(names) + 1);
            }
            return cases;
        };
    }
    if (["Class", "Struct"].indexOf(this.kind) !== -1 && canonicalType) {
        this.fields = function fields() {
            let results = [];
            let hierarchy = [canonicalType];
            while (hierarchy[hierarchy.length - 1].superClass) {
                hierarchy.push(hierarchy[hierarchy.length - 1].superClass);
            }
            let offset = ptr(0);
            for (let i = hierarchy.length; i--;) {
                let canon = hierarchy[i];
                let nomin = (["Class", "Struct"].indexOf(canon.kind) != -1) ? canon.getNominalTypeDescriptor() : null;
                if (!nomin)
                    continue;
                let info = (nomin.getKind() === "Class") ? nomin.clas : nomin.struct;
                if (!info.hasFieldOffsetVector())
                    throw new Error("fields without offset vector not implemented");

                let fieldTypeAccessor = new NativeFunction(info.getFieldTypes, 'pointer', ['pointer']);
                let fieldTypes = fieldTypeAccessor(canon._ptr);

                let fieldName = info.fieldNames;
                let fieldOffsets = canon._ptr.add(info.fieldOffsetVectorOffset * Process.pointerSize);
                for (let j = 0; j < info.numFields; j++) {
                    let type = Memory.readPointer(fieldTypes.add(j * Process.pointerSize));
                    let typeFlags = type.and(types.FieldTypeFlags.typeMask);
                    type = new types.TargetMetadata(type.and(~types.FieldTypeFlags.typeMask));
                    let curOffset = Memory.readPointer(fieldOffsets.add(j * Process.pointerSize));

                    results.push({
                        name: Memory.readUtf8String(fieldName),
                        offset: offset.add(curOffset),
                        type: new Type(null, type, "?Unknown type of " +  this.toString()),
                        weak: (typeFlags & types.FieldTypeFlags.Weak) === types.FieldTypeFlags.Weak,
                    });
                    fieldName = fieldName.add(strlen(fieldName) + 1);
                }
            }
            return results;
        };
    }
    if (canonicalType) {
        switch (this.toString()) {
            case "Swift.String":
                this.fromJS = function (address, value) {
                    // TODO: fromJS needs a parameter telling it whether it is initializing or assigning
                    canonicalType.valueWitnessTable.destroy(address, canonicalType._ptr);
                    let cStr = Memory.allocUtf8String(value);
                    api.swift_stringFromUTF8InRawMemory(address, cStr, value.length);
                    return true;
                };
            case "Swift.Bool":
                this.toJS = function (address) { return Memory.readU8(address) !== 0; };
                this.fromJS = function (address, value) { Memory.writeU8(address, value ? 1 : 0); return true; };
                this.getSize = function getSize() { return 1; };
                break;
            case "Swift.UInt":
                this.toJS = function(pointer) { return Memory.readULong(pointer); };
                this.fromJS = function(pointer, value) { Memory.writeULong(pointer, value); return true; };
                this.getSize = function() { return Process.pointerSize; };
                break;
            case "Swift.Int":
                this.toJS = function(pointer) { return Memory.readLong(pointer); };
                this.fromJS = function(pointer, value) { Memory.writeLong(pointer, value); return true; };
                this.getSize = function() { return Process.pointerSize; };
                break;
            case "Swift.Int8":
            case "Swift.Int16":
            case "Swift.Int32":
            case "Swift.Int64":
            case "Swift.Int128":
            case "Swift.Int256":
            case "Swift.Int512":
            case "Swift.UInt8":
            case "Swift.UInt16":
            case "Swift.UInt32":
            case "Swift.UInt64":
            case "Swift.UInt128":
            case "Swift.UInt256":
            case "Swift.UInt512":
            case "Swift.RawPointer":
                this.toJS = (pointer) => this.fields()[0].type.toJS(pointer);
                this.fromJS = (pointer, value) => this.fields()[0].type.fromJS(pointer, value);
                this.getSize = () => this.fields()[0].type.getSize();
                break
        }

        Object.defineProperty(this, 'Type', {
            enumerable: true,
            get() {
                let meta;
                if (this.kind === "Existential" || this.kind === "ExistentialMetatype") {
                    meta = _api.swift_getExistentialMetatypeMetadata(canonicalType._ptr);
                } else {
                    meta = _api.swift_getMetatypeMetadata(canonicalType._ptr);
                }
                return new Type(null, new types.TargetMetadata(meta), this.toString() + ".Type");
            },
        });
    }
    if (this.kind === "Existential" && canonicalType) {
        this.protocols = function protocols() {
            return canonicalType.protocols.map(getOrMakeProtocolType);
        };
        this.combineWith = function combineWith(other) {
            if (other.kind !== "Existential")
                throw new Error("can only combine existential types with each other");
            let protos = canonicalType.protocols.concat(other.canonicalType.protocols);
            // TODO: this is wrong, at least for protocols defined in nested contexts (see TypeDecl::compare)
            protos.sort(function(p1, p2) {
                if (p1.name < p2.name)
                    return -1;
                if (p1.name > p2.name)
                    return 1;
                return p1._ptr.compare(p2._ptr)
            });
            for (let i = 1; i < protos.length; i++) {
                if (protos[i - 1]._ptr.toString() === protos[i]._ptr.toString()) {
                    protos.splice(i, 1);
                    i--;
                }
            }

            let arr = Memory.alloc(protos.length * Process.pointerSize);
            _leakedMemory.push(arr);
            let names = [];
            for (let i = 0; i < protos.length; i++) {
                Memory.writePointer(arr.add(i * Process.pointerSize), protos[i]._ptr);
                names.push(protos[i].name);
            }

            let bound = (canonicalType.isClassBounded() || other.canonicalType.isClassBounded()) ? "Class" : "Any";
            bound = types.ProtocolClassConstraint[bound];

            let superClass = canonicalType.getSuperclassConstraint();
            superClass = superClass === null ? ptr(0) : superClass._ptr;

            let canon = _api.swift_getExistentialTypeMetadata(bound, superClass, protos.length, arr);
            return new Type(null, new types.TargetMetadata(canon), names.join(" + "));
        };
        if (!canonicalType.isClassBounded()) {
            this.withClassBound = function withClassBound() {
                let protocols = canonicalType.protocols;
                let canon = _api.swift_getExistentialTypeMetadata(types.ProtocolClassConstraint.Class,
                    superType.canonicalType._ptr, protocols.length, protocols.arrayLocation);
                return new Type(null, new types.TargetMetadata(canon));
            };
        }
        if (!canonicalType.getSuperclassConstraint() && !canonicalType.isObjC()) {
            this.withSuperclassConstraint = function withSuperclassConstraint(superType) {
                let protocols = canonicalType.protocols;
                let canon = _api.swift_getExistentialTypeMetadata(types.ProtocolClassConstraint.Class,
                    superType.canonicalType._ptr, protocols.length, protocols.arrayLocation);
                return new Type(null, new types.TargetMetadata(canon));
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
            throw new Error("a name is required when creating Opaque types");
        this.fixedName = name;

        this.getCType = function getCType() {
            const knownTypes = {
                "Builtin.Int8": "int8",
                "Builtin.Int16": "int16",
                "Builtin.Int32": "int32",
                "Builtin.Int64": "int64",
                "Builtin.UInt8": "uint8",
                "Builtin.UInt16": "uint16",
                "Builtin.UInt32": "uint32",
                "Builtin.UInt64": "uint64",
                "Builtin.RawPointer": "pointer",
                // TODO: others (git grep -wE 'Builtin\.\w+' | grep -owE 'Builtin\.[A-Z]\w+' | sort -u)
            };
            return knownTypes[this.fixedName];
        };
        this.getSize = function getSize() {
            const knownSizes = {
                "Builtin.Int8": 1,
                "Builtin.Int16": 2,
                "Builtin.Int32": 4,
                "Builtin.Int64": 8,
                "Builtin.Int128": 16,
                "Builtin.Int256": 32,
                "Builtin.Int512": 64,
                "Builtin.UInt8": 1,
                "Builtin.UInt16": 2,
                "Builtin.UInt32": 4,
                "Builtin.UInt64": 8,
                "Builtin.UInt128": 16,
                "Builtin.UInt256": 32,
                "Builtin.UInt512": 64,
                "Builtin.RawPointer": Process.pointerSize,
                // TODO: others (git grep -wE 'Builtin\.\w+' | grep -owE 'Builtin\.[A-Z]\w+' | sort -u)
            };
            return knownSizes[this.fixedName];
        };
        this.toJS = function toJS(pointer) {
            if (this.fixedName === "Builtin.RawPointer") {
                return Memory.readPointer(pointer);
            }

            let size = this.getSize();
            if (size === undefined || size > 8)
                return undefined;
            if (this.fixedName.indexOf("Builtin.Int") === 0) {
                return Memory['readS' + size*8](pointer);
            } else if (this.fixedName.indexOf("Builtin.UInt") === 0) {
                return Memory['readU' + size*8](pointer);
            }

            return undefined;
        };
        this.fromJS = function fromJS(address, value) {
            if (this.fixedName === "Builtin.RawPointer") {
                Memory.writePointer(address, value);
                return true;
            }

            let size = this.getSize();
            if (size === undefined || size > 8)
                return false;
            if (this.fixedName.indexOf("Builtin.Int") === 0) {
                Memory['writeS' + size*8](address, value);
                return true;
            } else if (this.fixedName.indexOf("Builtin.UInt") === 0) {
                Memory['writeU' + size*8](address, value);
                return true;
            }

            return false;
        };
    }

    if (canonicalType && (this.kind !== "Class" || canonicalType.isTypeMetadata())) {
        let size = canonicalType.valueWitnessTable.size; // TODO: Swift doesn't count the static overhead of classes here
        this.getSize = function() { return size };
        this.stride = canonicalType.valueWitnessTable.stride;
        this.valueFlags = canonicalType.valueWitnessTable.flags;

        this.getGenericParams = function getGenericParams() {
            if (!canonicalType.getGenericArgs)
                throw new Error("generic arguments for this kind of type not implemented");
            return canonicalType.getGenericArgs().map(t => t === null ? null : new Type(null, t));
        };
    }
    if (this.kind === "ObjCClassWrapper") {
        this.getObjCObject = function getObjCObject() {
            return ObjC.Object(canonicalType.class_);
        };
    }

    if (canonicalType && ["Class", "Struct", "Enum"].indexOf(this.kind) !== -1) {
        this.defineMethod = function defineMethod(address, name, type) {
            // TODO: mutating or normal method?
            if (type.kind !== "Function")
                throw new Error("invalid type to act as method signature");
            this._methods.set(name, {'address': address, 'returnType': type.returnType(), 'args': type.getArguments(),
                'doesThrow': type.flags.doesThrow});
        };
        this._methods = new Map();
    }

    if (!this.isGeneric()) {
        if (!canonicalType) {
            return this.withGenericParams();
        } else {
            let func = swiftValue.makeSwiftValue(this);
            Object.defineProperties(func, Object.getOwnPropertyDescriptors(this));
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
        if ("_name" in this)
            return this._name;

        if (this.canonicalType) {
            let [pointer, len] = _api.swift_getTypeName(this.canonicalType._ptr, /* qualified? */ 1);
            let str = Memory.readUtf8String(pointer, len.toInt32());
            if (str.length !== 0 && str !== "<<< invalid type >>>") {
                this._name = str;
                return str;
            }
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
            this._name = name;
            return name;
        }

        if (this.fixedName) {
            this._name = this.fixedName;
            return this.fixedName;
        }
        this._name = "<<< invalid type >>>";
        return "<<< invalid type >>>";
        //throw new Error(`cannot get string representation for type without nominal or canonical type information`);
    },
};


function findAllTypes(api) {
    let sizeAlloc = Memory.alloc(8);
    const __TEXT = Memory.allocUtf8String("__TEXT");

    const sectionNames = [Memory.allocUtf8String("__swift2_types"), Memory.allocUtf8String("__swift2_proto")];
    const recordSizes = [8, 16];

    function getTypePrio(t) {
        if (t.canonicalType)
            return 0;
        if (t.nominalType)
            return 1;
        if (t.accessFunction)
            return 2;
        throw new Error("invalid state of type object");
    }
    let newTypes = [];
    function addType(t) {
        let name = t.toString();
        let other = typesByName.get(name);
        if (!other || getTypePrio(t) < getTypePrio(other)) {
            typesByName.set(name, t);
            newTypes.push(t);
        }
    }

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
                    addType(getOrMakeProtocolType(record.protocol));
                }
                let nominalType = null;
                if (record.getTypeKind() === types.TypeMetadataRecordKind.UniqueNominalTypeDescriptor)
                    nominalType = record.getNominalTypeDescriptor();

                let canonicalType = record.getCanonicalTypeMetadata(api);

                if (nominalType || canonicalType) {
                    addType(new Type(nominalType, canonicalType));
                } else {
                    console.log(`metadata record without nominal or canonical type?! @${pointer.add(i)} of section ${section} in ${mod.name} ${record.getTypeKind()}`);
                }
            }
        }

        // TODO: it kind of sucks that we rely on symbol information here.
        // we should see if there is some other way to find the nominal types for generic data types
        const METADATA_PREFIX = "type metadata for ";
        const METADATA_ACCESSOR_PREFIX = "type metadata accessor for ";
        const NOMINAL_PREFIX = "nominal type descriptor for ";
        for (let exp of Module.enumerateExportsSync(mod.name)) {
            if (Swift.isSwiftName(exp.name)) {
                let demangled = Swift.demangle(exp.name);
                if (demangled.startsWith(METADATA_PREFIX)) {
                    let name = demangled.substr(METADATA_PREFIX.length);
                    // type metadata sometimes can have members at negative indices, so we need to
                    // iterate until we find something that looks like the beginning of a Metadata object
                    // (Sadly, that doesn't work for class metadata with ISA pointers, but it should be no
                    // problem to find ObjC metadata for such classes.)
                    for (let i = 0; i < 2; i++) {
                        let ptr = exp.address.add(Process.pointerSize * i);
                        if (Memory.readPointer(ptr).toString(10) in types.MetadataKind) {
                            addType(new Type(null, new types.TargetMetadata(ptr), name));
                            break;
                        }
                    }
                } else if (demangled.startsWith(NOMINAL_PREFIX)) {
                    let name = demangled.substr(NOMINAL_PREFIX.length);
                    addType(new Type(new types.TargetNominalTypeDescriptor(exp.address), null, name));
                } else if (demangled.startsWith(METADATA_ACCESSOR_PREFIX)) {
                    let name = demangled.substr(METADATA_ACCESSOR_PREFIX.length);
                    addType(new Type(null, null, name, exp.address));
                }
            }
        }

    }

    if (!typesByName.has("Any")) {
        let Any = _api.swift_getExistentialTypeMetadata(types.ProtocolClassConstraint.Any, /*superClass*/ ptr(0), /*numProtocols*/ 0, /*protcols*/ ptr(0));
        Any = new Type(null, new types.TargetMetadata(Any), "Any");
        typesByName.set("Any", Any);
    }
    if (!typesByName.has("Swift.AnyObject")) {
        let AnyObject = _api.swift_getExistentialTypeMetadata(types.ProtocolClassConstraint.Class, /*superClass*/ ptr(0), /*numProtocols*/ 0, /*protcols*/ ptr(0));
        AnyObject = new Type(null, new types.TargetMetadata(AnyObject), "Swift.AnyObject");
        typesByName.set("Swift.AnyObject", AnyObject);
    }
    if (!typesByName.has("Swift.AnyObject.Type")) {
        let AnyObject = typesByName.get("Swift.AnyObject");
        let AnyClass = AnyObject.Type;
        typesByName.set("Swift.AnyObject.Type", AnyClass);
        typesByName.set("Swift.AnyClass", AnyClass);
    }

    while (newTypes.length) {
        let type = newTypes.pop();
        if ('enumCases' in type)
            type.enumCases().filter(i => i.type).forEach(i => addType(i.type));
        if ('fields' in type)
            type.fields().filter(i => i.type).forEach(i => addType(i.type));
        if ('tupleElements' in type)
            type.tupleElements().filter(i => i.type).forEach(i => addType(i.type));
        if ('getArguments' in type)
            type.getArguments().filter(i => i.type).forEach(i => addType(i.type));
        if ('returnType' in type)
            addType(type.returnType());
        if (type.kind === "Class" && type.canonicalType && type.canonicalType.superClass)
            addType(new Type(null, type.canonicalType.superClass));
        if (type.kind === "Existential" && type.canonicalType) {
            for (let proto of type.canonicalType.protocols) {
                addType(getOrMakeProtocolType(proto));
                for (let inherited of proto.inheritedProtocols) {
                    addType(getOrMakeProtocolType(inherited));
                }
            }
            if (type.canonicalType.getSuperclassConstraint())
                addType(new Type(null, type.canonicalType.getSuperclassConstraint()));
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
        let typesByName = findAllTypes(this._api);

        this._typesByName = typesByName;
        return Array.from(typesByName.values());
    },

    makeTupleType(labels, innerTypes) {
        if (innerTypes.length != labels.length)
            throw new Error("labels array and innerTypes array need the same length!");
        let elements = innerTypes.length ? Memory.alloc(Process.pointerSize * innerTypes.length) : ptr(0);
        let labelsStr = Memory.allocUtf8String(labels.join(" ") + " ");
        _leakedMemory.push(labelsStr); // if the tuple type is new, we must not ever dealllocate this string
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
