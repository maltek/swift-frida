const metadata = require('./metadata');
const swiftValue = require('./swift-value');

function strlen(pointer) {
    let i;
    for (i = 0; Memory.readU8(pointer.add(i)) !== 0; i++) {
    }
    return i;
}

let _leakedMemory = []; // some runtime functions take pointers that must remain valid forever

const typesByCanonical = new Map();
const protocolTypes = new Map();
function getOrMakeProtocolType(proto) {
    let existing = protocolTypes.get(proto._ptr.toString());
    if (existing) {
        return existing;
    }

    let arr = Memory.alloc(Process.pointerSize);
    Memory.writePointer(arr, proto._ptr);

    let canonical = Swift._api.swift_getExistentialTypeMetadata(metadata.ProtocolClassConstraint.Any,
        /*superClass*/ptr(0), /*numProtocols*/ 1, arr);
    canonical = new metadata.TargetMetadata(canonical);

    if (canonical.protocols.arrayLocation.toString() === arr.toString()) {
        _leakedMemory.push(arr);
    }

    let name = Swift.isSwiftName(proto.name) ? Swift.demangle(proto.name) : proto.name;
    let type = new Type(null, canonical, name);
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
        this.fromJS = function (address, value) { Swift._api.objc_storeStrong(address, value); return true; };
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
            return new Type(this.nominalType, new metadata.TargetMetadata(canonical), name);
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
                    typeFlags = type.and(metadata.FieldTypeFlags.typeMask);
                    type = new metadata.TargetMetadata(type.and(~metadata.FieldTypeFlags.typeMask));
                }
                cases.push({
                    tag: i - payloadCount,
                    name: names === null ? null : Memory.readUtf8String(names),
                    type: type === null ? null : new Type(null, type),
                    indirect: (typeFlags & metadata.FieldTypeFlags.Indirect) === metadata.FieldTypeFlags.Indirect,
                    weak: (typeFlags & metadata.FieldTypeFlags.Weak) === metadata.FieldTypeFlags.Weak,
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
                    let typeFlags = type.and(metadata.FieldTypeFlags.typeMask);
                    type = new metadata.TargetMetadata(type.and(~metadata.FieldTypeFlags.typeMask));
                    let curOffset = Memory.readPointer(fieldOffsets.add(j * Process.pointerSize));
                    let fieldNameStr = Memory.readUtf8String(fieldName);

                    results.push({
                        name: fieldNameStr,
                        offset: offset.add(curOffset),
                        type: new Type(null, type, `?Unknown type of ${this}.${fieldNameStr}`),
                        weak: (typeFlags & metadata.FieldTypeFlags.Weak) === metadata.FieldTypeFlags.Weak,
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
                    meta = Swift._api.swift_getExistentialMetatypeMetadata(canonicalType._ptr);
                } else {
                    meta = Swift._api.swift_getMetatypeMetadata(canonicalType._ptr);
                }
                return new Type(null, new metadata.TargetMetadata(meta), this.toString() + ".Type");
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
            bound = metadata.ProtocolClassConstraint[bound];

            let superClass = canonicalType.getSuperclassConstraint();
            superClass = superClass === null ? ptr(0) : superClass._ptr;

            let canon = Swift._api.swift_getExistentialTypeMetadata(bound, superClass, protos.length, arr);
            return new Type(null, new metadata.TargetMetadata(canon), names.join(" + "));
        };
        if (canonicalType.isClassBounded()) {
            this.withoutClassBound = function withoutClassBound() {
                let protocols = canonicalType.protocols;
                let canon = Swift._api.swift_getExistentialTypeMetadata(metadata.ProtocolClassConstraint.Any,
                    ptr(0), protocols.length, protocols.arrayLocation);
                return new Type(null, new metadata.TargetMetadata(canon));
            };
        } else {
            this.withClassBound = function withClassBound() {
                let protocols = canonicalType.protocols;
                let canon = Swift._api.swift_getExistentialTypeMetadata(metadata.ProtocolClassConstraint.Class,
                    ptr(0), protocols.length, protocols.arrayLocation);
                return new Type(null, new metadata.TargetMetadata(canon));
            };
        }
        if (!canonicalType.isObjC()) {
            if (canonicalType.getSuperclassConstraint()) {
                this.withoutSuperclassConstraint = function withoutSuperclassConstraint() {
                    let protocols = canonicalType.protocols;
                    let canon = Swift._api.swift_getExistentialTypeMetadata(metadata.ProtocolClassConstraint.Class,
                        ptr(0), protocols.length, protocols.arrayLocation);
                    return new Type(null, new metadata.TargetMetadata(canon));
                };
            } else {
                this.withSuperclassConstraint = function withSuperclassConstraint(superType) {
                    let protocols = canonicalType.protocols;
                    let canon = Swift._api.swift_getExistentialTypeMetadata(metadata.ProtocolClassConstraint.Class,
                        superType.canonicalType._ptr, protocols.length, protocols.arrayLocation);
                    return new Type(null, new metadata.TargetMetadata(canon));
                };
            }
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
    if (canonicalType && this.kind === "Class") {
        this.superClass = function superClass() {
            let canon = canonicalType.superClass;
            if (canon === null)
                return null;
            return new Type(null, canon, `?superClass of ${this}`);
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
            let [pointer, len] = Swift._api.swift_getTypeName(this.canonicalType._ptr, /* qualified? */ 1);
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
                if (this.canonicalType && "getGenericParams" in this) {
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
    let typesByName = new Map();

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
        if (t === null)
            return;

        let name = t.toString();
        let other = typesByName.get(name);
        if (!other || getTypePrio(t) < getTypePrio(other)) {
            typesByName.set(name, t);
            newTypes.push(t);
        }
    }

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
                    record = new metadata.TargetTypeMetadataRecord(pointer.add(i));
                } else {
                    record = new metadata.TargetProtocolConformanceRecord(pointer.add(i));
                    addType(getOrMakeProtocolType(record.protocol));
                }
                let nominalType = null;
                if (record.getTypeKind() === metadata.TypeMetadataRecordKind.UniqueNominalTypeDescriptor)
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
                        if (Memory.readPointer(ptr).toString(10) in metadata.MetadataKind) {
                            addType(new Type(null, new metadata.TargetMetadata(ptr), name));
                            break;
                        }
                    }
                } else if (demangled.startsWith(NOMINAL_PREFIX)) {
                    let name = demangled.substr(NOMINAL_PREFIX.length);
                    addType(new Type(new metadata.TargetNominalTypeDescriptor(exp.address), null, name));
                } else if (demangled.startsWith(METADATA_ACCESSOR_PREFIX)) {
                    let name = demangled.substr(METADATA_ACCESSOR_PREFIX.length);
                    addType(new Type(null, null, name, exp.address));
                }
            }
        }

    }

    if (!typesByName.has("Any")) {
        let Any = Swift._api.swift_getExistentialTypeMetadata(metadata.ProtocolClassConstraint.Any, /*superClass*/ ptr(0), /*numProtocols*/ 0, /*protcols*/ ptr(0));
        Any = new Type(null, new metadata.TargetMetadata(Any), "Any");
        typesByName.set("Any", Any);
    }
    if (!typesByName.has("Swift.AnyObject")) {
        let AnyObject = Swift._api.swift_getExistentialTypeMetadata(metadata.ProtocolClassConstraint.Class, /*superClass*/ ptr(0), /*numProtocols*/ 0, /*protcols*/ ptr(0));
        AnyObject = new Type(null, new metadata.TargetMetadata(AnyObject), "Swift.AnyObject");
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
        if ('superClass' in type)
            addType(type.superClass());
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

module.exports = {
    findAllTypes,
    Type,
};
