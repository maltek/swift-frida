"use strict";

/* jshint esnext: true, evil: true */

const mangling = require('./mangling');

// for all these definitions, look at include/swift/Runtime/Metadata.h and friends in the Swift sources
// based on commit 2035c311736d15c9ef1a7e2e42a925a6ddae098c

function flagsToObject(definition, value) {
    let res = {};
    for (let [flagName, flagVal] of Object.entries(definition)) {
        res[flagName] = (value & flagVal) === flagVal;
    }
    return res;
}

const ValueWitnessFlags = {
    AlignmentMask: 0x0000FFFF,
    IsNonPOD: 0x00010000,
    IsNonInline: 0x00020000,
    HasExtraInhabitants: 0x00040000,
    HasSpareBits: 0x00080000,
    IsNonBitwiseTakable: 0x00100000,
    HasEnumWitnesses: 0x00200000,
};

function TypeLayout(pointer) {
    this._ptr = pointer;
}
TypeLayout.prototype = {
    // offset 0
    get size() {
        return Memory.readPointer(this._ptr.add(0));
    },
    // offset pointerSize
    get flags() {
        return flagsToObject(ValueWitnessFlags, Memory.readPointer(this._ptr.add(Process.pointerSize)).toInt32());
    },
    // offset 2* pointerSize
    get stride() {
        return Memory.readPointer(this._ptr.add(2 * Process.pointerSize));
    },
    // offset 3* pointerSize
    get extraInhabitantFlags() {
        if (!this.flags.HasExtraInhabitants)
            throw new Error("extra inhabitant flag not available");
        return Memory.readPointer(this._ptr.add(3 * Process.pointerSize));
    },
};
function ValueWitnessTable(pointer) {
    TypeLayout.call(this, pointer.add(17 * Process.pointerSize));
    this._vwt = pointer;
}
ValueWitnessTable.prototype = Object.create(TypeLayout.prototype, {
    // offset 0
    destroyBuffer: {
        get() {
            // void destroyBuffer(ValueBuffer *buffer, const Metadata *self);
            return new NativeFunction(Memory.readPointer(this._vwt.add(0)), 'void', ['pointer', 'pointer']);
        },
        enumerable: true,
    },
    // offset pointerSize
    initializeBufferWithCopyOfBuffer: {
        get() {
            // OpaqueValue *initializeBufferWithCopyOfBuffer(ValueBuffer *dest, ValueBuffer *src, const Metadata *self)
            return new NativeFunction(Memory.readPointer(this._vwt.add(1*Process.pointerSize)), 'pointer',
                                                         ['pointer', 'pointer', 'pointer']);
        },
        enumerable: true,
    },
    // offset 2*pointerSize
    projectBuffer: {
        get() {
            // OpaqueValue *projectBuffer(ValueBuffer *buffer, const Metadata *self)
            return new NativeFunction(Memory.readPointer(this._vwt.add(2*Process.pointerSize)), 'pointer',
                                                         ['pointer', 'pointer']);
        },
        enumerable: true,
    },
    // offset 3*pointerSize
    deallocateBuffer: {
        get() {
            // void deallocateBuffer(ValueBuffer *buffer, const Metadata *self)
            return new NativeFunction(Memory.readPointer(this._vwt.add(3*Process.pointerSize)), 'void',
                                                         ['pointer', 'pointer']);
        },
        enumerable: true,
    },
    // offset 4*pointerSize
    destroy: {
        get() {
            // void destroy(OpaqueValue *object, const Metadata *self)
            return new NativeFunction(Memory.readPointer(this._vwt.add(4*Process.pointerSize)), 'void',
                                                         ['pointer', 'pointer']);
        },
        enumerable: true,
    },
    // offset 5*pointerSize
    initializeBufferWithCopy: {
        get() {
            // OpaqueValue *initializeBufferWithCopy(ValueBuffer *dest, OpaqueValue *src, const Metadata *self)
            return new NativeFunction(Memory.readPointer(this._vwt.add(5*Process.pointerSize)), 'pointer',
                                                         ['pointer', 'pointer', 'pointer']);
        },
        enumerable: true,
    },
    // offset 6*pointerSize
    initializeWithCopy: {
        get() {
            // OpaqueValue *initializeWithCopy(OpaqueValue *dest, OpaqueValue *src, const Metadata *self)
            return new NativeFunction(Memory.readPointer(this._vwt.add(6*Process.pointerSize)), 'pointer',
                                                         ['pointer', 'pointer', 'pointer']);
        },
        enumerable: true,
    },
    // offset 7*pointerSize
    assignWithCopy: {
        get() {
            // OpaqueValue *assignWithCopy(OpaqueValue *dest, OpaqueValue *src, const Metadata *self)
            return new NativeFunction(Memory.readPointer(this._vwt.add(7*Process.pointerSize)), 'pointer',
                                                         ['pointer', 'pointer', 'pointer']);
        },
        enumerable: true,
    },
    // offset 8*pointerSize
    initializeBufferWithTake: {
        get() {
            // OpaqueValue *initializeBufferWithTake(ValueBuffer *dest, OpaqueValue *src, const Metadata *self)
            return new NativeFunction(Memory.readPointer(this._vwt.add(8*Process.pointerSize)), 'pointer',
                                                         ['pointer', 'pointer', 'pointer']);
        },
        enumerable: true,
    },
    // offset 9*pointerSize
    initializeWithTake: {
        get() {
            // OpaqueValue *initializeWithTake(OpaqueValue *dest, OpaqueValue *src, const Metadata *self)
            return new NativeFunction(Memory.readPointer(this._vwt.add(9*Process.pointerSize)), 'pointer',
                                                         ['pointer', 'pointer', 'pointer']);
        },
        enumerable: true,
    },
    // offset 10*pointerSize
    assignWithTake: {
        get() {
            // OpaqueValue *assignWithTake(OpaqueValue *dest, OpaqueValue *src, const Metadata *self)
            return new NativeFunction(Memory.readPointer(this._vwt.add(10*Process.pointerSize)), 'pointer',
                                                         ['pointer', 'pointer', 'pointer']);
        },
        enumerable: true,
    },
    // offset 11*pointerSize
    allocateBuffer: {
        get() {
            // OpaqueValue *allocateBuffer(ValueBuffer *buffer, const Metadata *self)
            return new NativeFunction(Memory.readPointer(this._vwt.add(11*Process.pointerSize)), 'pointer',
                                                         ['pointer', 'pointer']);
        },
        enumerable: true,
    },
    // offset 12*pointerSize
    initializeBufferWithTakeOfBuffer: {
        get() {
            // OpaqueValue *initializeBufferWithTakeOfBuffer(ValueBuffer *dest, ValueBuffer *src, const Metadata *self)
            return new NativeFunction(Memory.readPointer(this._vwt.add(12*Process.pointerSize)), 'pointer',
                                                         ['pointer', 'pointer', 'pointer']);
        },
        enumerable: true,
    },
    // offset 13*pointerSize
    destroyArray: {
        get() {
            // void destroyArray(OpaqueValue *array, size_t n, const Metadata *self)
            return new NativeFunction(Memory.readPointer(this._vwt.add(13*Process.pointerSize)), 'pointer',
                                                         ['pointer', 'pointer', 'pointer']);
        },
        enumerable: true,
    },
    // offset 14*pointerSize
    initializeArrayWithCopy: {
        get() {
            // OpaqueValue *initializeArrayWithCopy(OpaqueValue *dest, OpaqueValue *src, size_t n, const Metadata *self)
            return new NativeFunction(Memory.readPointer(this._vwt.add(14*Process.pointerSize)), 'pointer',
                                                         ['pointer', 'pointer', 'pointer', 'pointer']);
        },
        enumerable: true,
    },
    // offset 15*pointerSize
    initializeArrayWithTakeFrontToBack: {
        get() {
            // OpaqueValue *initializeArrayWithTakeFrontToBack(OpaqueValue *dest, OpaqueValue *src, size_t n, const Metadata *self)
            return new NativeFunction(Memory.readPointer(this._vwt.add(15*Process.pointerSize)), 'pointer',
                                                         ['pointer', 'pointer', 'pointer', 'pointer']);
        },
        enumerable: true,
    },
    // offset 16*pointerSize
    initializeArrayWithTakeBackToFront: {
        get() {
            // OpaqueValue *initializeArrayWithTakeBackToFront(OpaqueValue *dest, OpaqueValue *src, size_t n, const Metadata *self)
            return new NativeFunction(Memory.readPointer(this._vwt.add(16*Process.pointerSize)), 'pointer',
                                                         ['pointer', 'pointer', 'pointer', 'pointer']);
        },
        enumerable: true,
    },
    isValueInline: {
        value: function(size, alignment) {
            if (size !== undefined && alignment !== undefined)
                return (size <= 3 * Process.pointerSize && alignment <= Process.pointerSize);
            else if (size !== undefined)
                throw new Error("no overload with 1 argument");
            else
                return !this.flags.IsNonInline;
        },
        enumerable: true,
    },
});

function TargetProtocolConformanceRecord(ptr) {
    this._ptr = ptr;
}
TargetProtocolConformanceRecord.prototype = {
    // offset 0
    get protocol() {
        return RelativeIndirectablePointer(this._ptr.add(0));
    },
    // offset 4
    get directType() {
        return RelativeIndirectablePointer(this._ptr.add(4));
    },
    get indirectClass() {
        return RelativeIndirectablePointer(this._ptr.add(4));
    },
    get typeDescriptor() {
        return RelativeIndirectablePointer(this._ptr.add(4));
    },

    // offset 8
    get witnessTable() {
        return RelativeDirectPointer(this._ptr.add(8));
    },
    get witnessTableAccessor() {
        return RelativeDirectPointer(this._ptr.add(8));
    },

    // offset 12
    get flags() {
        return Memory.readU32(this._ptr.add(12));
    },


    getTypeKind() {
        const TypeKindMask = 0x0000000F;
        const TypeKindShift = 0;
        return (this.flags & TypeKindMask) >>> TypeKindShift; // see TypeMetadataRecordKind
    },
    getConformanceKind() {
        const ConformanceKindMask = 0x00000010;
        const ConformanceKindShift = 4;
        return (this.flags & ConformanceKindMask) >>> ConformanceKindShift; // see ProtocolConformanceFlags
    },

    getDirectType() {
        switch(this.getTypeKind()) {
            case TypeMetadataRecordKind.Universal:
                return null;
            case TypeMetadataRecordKind.UniqueDirectType:
            case TypeMetadataRecordKind.NonuniqueDirectType:
              break;

            case TypeMetadataRecordKind.UniqueDirectClass:
            case TypeMetadataRecordKind.UniqueIndirectClass:
            case TypeMetadataRecordKind.UniqueNominalTypeDescriptor:
              throw new Error("not direct type metadata");
        }
        return new TargetMetadata(this.directType);
    },

    getDirectClass() {
        switch(this.getTypeKind()) {
            case TypeMetadataRecordKind.Universal:
                return null;
            case TypeMetadataRecordKind.UniqueDirectClass:
                break;

            case TypeMetadataRecordKind.UniqueDirectType:
            case TypeMetadataRecordKind.NonuniqueDirectType:
            case TypeMetadataRecordKind.UniqueNominalTypeDescriptor:
            case TypeMetadataRecordKind.UniqueIndirectClass:
              throw new Error("not direct class object");
        }
        return this.directType;
    },

    getIndirectClass() {
        switch(this.getTypeKind()) {
            case TypeMetadataRecordKind.Universal:
                return null;
            case TypeMetadataRecordKind.UniqueIndirectClass:
              break;

            case TypeMetadataRecordKind.UniqueDirectType:
            case TypeMetadataRecordKind.UniqueDirectClass:
            case TypeMetadataRecordKind.NonuniqueDirectType:
            case TypeMetadataRecordKind.UniqueNominalTypeDescriptor:
              throw new Error("not indirect class object");
        }
        return this.indirectClass;
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
                throw new Error("not generic metadata pattern");
        }

        return new TargetNominalTypeDescriptor(this.typeDescriptor);
    },

    /// Get the directly-referenced static witness table.
    getStaticWitnessTable() {
        switch (this.getConformanceKind()) {
            case ProtocolConformanceReferenceKind.WitnessTable:
                break;

            case ProtocolConformanceReferenceKind.WitnessTableAccessor:
                throw new Error("not witness table");
        }
        return this.witnessTable;
    },

    getWitnessTableAccessor() {
        switch (this.getConformanceKind()) {
            case ProtocolConformanceReferenceKind.WitnessTableAccessor:
                break;

            case ProtocolConformanceReferenceKind.WitnessTable:
                throw new Error("not witness table accessor");
        }
        return new NativeFunction(this.witnessTableAccessor, 'pointer', ['pointer']);
    },

    getCanonicalTypeMetadata(api) {
        let classMetadata = null;
        switch (this.getTypeKind()) {
            case TypeMetadataRecordKind.UniqueDirectType:
                return this.getDirectType();
            case TypeMetadataRecordKind.NonuniqueDirectType:
                return new TargetMetadata(api.swift_getForeignTypeMetadata(this.getDirectType()._ptr));
            case TypeMetadataRecordKind.UniqueIndirectClass:
                classMetadata = Memory.readPointer(this.getIndirectClass());
                break;
            case TypeMetadataRecordKind.UniqueDirectClass:
                classMetadata = this.getDirectClass();
                break;
            case TypeMetadataRecordKind.UniqueNominalTypeDescriptor:
            case TypeMetadataRecordKind.Universal:
                return null;
        }
        if (classMetadata !== null && !classMetadata.isNull())
            return new TargetMetadata(api.swift_getObjCClassMetadata(classMetadata));
        return null;
    },
    getWitnessTable(type) {
        switch (this.getConformanceKind()) {
            case ProtocolConformanceReferenceKind.WitnessTable:
                return this.getStaticWitnessTable();

            case ProtocolConformanceReferenceKind.WitnessTableAccessor:
                return this.getWitnessTableAccessor()(this.type);
        }
    },
};
const ProtocolConformanceReferenceKind = {
    WitnessTable: 0,
    WitnessTableAccessor: 1,
};

const FieldTypeFlags = {
    Indirect: 1,
    Weak: 2,

    typeMask: 0x3,
};


const TypeMetadataRecordKind = {
    Universal: 0,
    UniqueDirectType: 1,
    NonuniqueDirectType: 2,
    UniqueIndirectClass : 3,
    UniqueNominalTypeDescriptor: 4,
    UniqueDirectClass: 0xF,
};

function FlaggedPointer(type, bitPos) {
    const flagMask = 1 << bitPos;
    const pointerBitMask = ~flagMask;
    return function(val) {
        return {
            pointer: new type(val.and(pointerBitMask)),
            flag: !val.and(flagMask).isNull(),
        };
    }
}
let Argument = FlaggedPointer(TargetMetadata, 0);

function RelativeDirectPointerIntPair(ptr) {
    let val = Memory.readS32(ptr);
    let offset = val & (~0x3);
    let intVal = val & 0x3;
    return {
        pointer: ptr.add(val & (~0x3)),
        intVal: val & 0x3,
    };
}
const NominalTypeKind = {
    "0": "Class",
    "1": "Struct",
    "2": "Enum",
    "3": "Optional",
};

const MetadataKind = {
    "0": "Class",
    "1": "Struct",
    "2": "Enum",
    "3": "Optional",

    "8": "Opaque",
    "9": "Tuple",
    "10": "Function",
    "12": "Existential",
    "13": "Metatype",
    "14": "ObjCClassWrapper",
    "15": "ExistentialMetatype",
    "16": "ForeignClass",
    "64": "HeapLocalVariable",
    "65": "HeapGenericLocalVariable",
    "128": "ErrorObject",
};

function TargetMetadata(pointer) {
    this._ptr = pointer;
    switch (this.kind) {
        case "Class":
            return new TargetClassMetadata(pointer);
        case "Struct":
            return new TargetValueMetadata(pointer);
        case "Enum":
        case "Optional":
            return new TargetEnumMetadata(pointer);
        case "Tuple":
            return new TargetTupleTypeMetadata(pointer);
        case "Function":
            return new TargetFunctionTypeMetadata(pointer);
        case "ForeignClass":
            return new TargetForeignTypeMetadata(pointer);
        case "ObjCClassWrapper":
            return new TargetObjCClassWrapperMetadata(pointer);
        case "Existential":
            return new TargetExistentialTypeMetadata(pointer);
    }
}
TargetMetadata.prototype = {
    // offset -pointerSize
    get valueWitnessTable() {
        return new ValueWitnessTable(Memory.readPointer(this._ptr.sub(Process.pointerSize)));
    },

    get kind() {
        let val = Memory.readPointer(this._ptr);
        if (val.compare(ptr(4096)) > 0) {
            return "Class";
        }
        return MetadataKind[val.toInt32().toString()];
    },

    getNominalTypeDescriptor() {
        return null;
    },

    toString() {
        return "[TargetMetadata: " + this.kind + "@" + this._ptr + "]";
    },
};
const ClassFlags = {
    IsSwift1: 0x1,
    UsesSwift1Refcounting: 0x2,
    HasCustomObjCName: 0x4,
};
function TargetClassMetadata(pointer) {
    this._ptr = pointer;
    if (this.kind !== "Class")
        throw new Error("type is not a class type");
}
TargetClassMetadata.prototype = Object.create(TargetMetadata.prototype, {
    // offset -2 * pointerSize
    destructor: {
        get() {
            if (this.isPureObjC()) throw new Error("destructor not available for ObjC classes");
            return Memory.readPointer(this._ptr.sub(2 * Process.pointerSize));
        },
        enumerable: true,
    },
    // offset -1 * pointerSize
    valueWitnessTable: {
        get() {
            if (this.isPureObjC()) throw new Error("valueWitnessTable not available for ObjC classes");
            return new ValueWitnessTable(Memory.readPointer(this._ptr.sub(Process.pointerSize)));
        },
        enumerable: true,
    },

    // offset 0
    isa: {
        get() {
            let val = Memory.readPointer(this._ptr);
            if (val.compare(ptr(4096)) <= 0) {
                return null;
            }
            return val;
        },
        enumerable: true,
    },
    // offset pointerSize
    superClass: {
        get() {
            if (this.isPureObjC())
                return null;
            let val = Memory.readPointer(this._ptr.add(Process.pointerSize));
            return val.isNull() ? null : new TargetClassMetadata(val);
        },
        enumerable: true,
    },
    // offset 2*pointerSize
    cacheData: {
        get() {
            return [
                Memory.readPointer(this._ptr.add(2 * Process.pointerSize)),
                Memory.readPointer(this._ptr.add(3 * Process.pointerSize)),
            ];
        },
        enumerable: true,
    },
    // offset 4 * pointerSize
    data: {
        get() {
            return Memory.readPointer(this._ptr.add(4 * Process.pointerSize));
        },
        enumerable: true,
    },
    // offset 5 * pointerSize
    flags: {
        get() {
            if (this.isPureObjC()) throw new Error("flags not available for ObjC classes");
            return flagsToObject(ClassFlags, Memory.readU32(this._ptr.add(5 * Process.pointerSize)));
        },
        enumerable: true,
    },
    // offset 5 * pointerSize + 4
    instanceAddressPoint: {
        get() {
            if (this.isPureObjC()) throw new Error("instanceAddressPoint not available for ObjC classes");
            return Memory.readU32(this._ptr.add(4 + 5 * Process.pointerSize));
        },
        enumerable: true,
    },
    // offset 5 * pointerSize + 8
    instanceSize: {
        get() {
            if (this.isPureObjC()) throw new Error("instanceSize not available for ObjC classes");
            return Memory.readU32(this._ptr.add(8 + 5 * Process.pointerSize));
        },
        enumerable: true,
    },
    // offset 5 * pointerSize + 12
    instanceAlignMask: {
        get() {
            if (this.isPureObjC()) throw new Error("instanceAlignMask not available for ObjC classes");
            return Memory.readU16(this._ptr.add(12 + 5 * Process.pointerSize));
        },
        enumerable: true,
    },
    // offset 5 * pointerSize + 14: reserved
    // offset 5 * pointerSize + 16
    classSize: {
        get() {
            if (this.isPureObjC()) throw new Error("classSize not available for ObjC classes");
            return Memory.readU32(this._ptr.add(16 + 5 * Process.pointerSize));
        },
        enumerable: true,
    },
    // offset 5 * pointerSize + 20
    classAddressPoint: {
        get() {
            if (this.isPureObjC()) throw new Error("classAddressPoint not available for ObjC classes");
            return Memory.readU32(this._ptr.add(20 + 5 * Process.pointerSize));
        },
        enumerable: true,
    },
    // offset 5 * pointerSize + 24
    description: {
        get() {
            if (this.isPureObjC()) throw new Error("description not available for ObjC classes");
            return ConstTargetFarRelativeDirectPointer(this._ptr.add(24 + 5 * Process.pointerSize));
        },
        enumerable: true,
    },
    // offset 6 * pointerSize + 24
    iVarDestroyer: {
        get() {
            if (this.isPureObjC()) throw new Error("iVarDestroyer not available for ObjC classes");
            return new NativePointer(Memory.readPointer(this._ptr.add(24 + 6 * Process.pointerSize)), 'void', ['pointer']);
        },
        enumerable: true,
    },
    // offset 7 * pointerSize + 24: superClass members (then superClass's superClass members...)
    //                          ... metadata reference for parent
    //                          ... generic parameters for this class
    //                          ... class variables
    //                          ... "tabulated" virtual methods

    isTypeMetadata: {
        value: function() {
            return this.data.and(ptr(1)).equals(ptr(1));
        },
        enumerable: true,
    },
    isPureObjC: {
        value: function() {
            return !this.isTypeMetadata();
        },
        enumerable: true,
    },
    isArtificialSubclass: {
        value: function() {
            return this.description.compare(int64(0)) === 0;
        },
        enumerable: true,
    },
    getDescription: {
        value: function() {
            if(!this.isTypeMetadata())
                throw new Error("assertion error");
            if(this.isArtificialSubclass())
                throw new Error("assertion error");
            return this.description;
        },
        enumerable: true,
    },
    getNominalTypeDescriptor: {
        value() {
            if (this.isTypeMetadata() && !this.isArtificialSubclass())
                return new TargetNominalTypeDescriptor(this.getDescription());
            else
                return null;
        },
        enumerable: true,
    },
    getParentType: {
        value(nominalType) {
            let genericParams = nominalType.genericParams;
            if (!genericParams.flags.HasParent)
                return null;

            return new TargetMetadata(this._ptr.add((genericParams.offset - 1) * Process.pointerSize));
        },
        enumerable: true,
    },
});
function TargetValueMetadata(pointer) {
    this._ptr = pointer;

    switch (this.kind) {
        case "Struct":
            break;
        default:
            throw new Error("type is not a value type");
    }
}
TargetValueMetadata.prototype = Object.create(TargetMetadata.prototype, {
    // offset pointerSize
    description: {
        get() {
            let val = ConstTargetFarRelativeDirectPointer(this._ptr.add(Process.pointerSize));
            if (val.isNull())
                return null;
            return val;
        },
        enumerable: true,
    },

    getGenericArgs: {
        value() {
            let params = this.getNominalTypeDescriptor().genericParams;
            let args = [];
            if (params.hasGenericRequirements()) {
                // the shift acts on signed 32bit numbers, like we need here
                let offset = params.offset << Math.log2(Process.pointerSize);
                for (let i = 0; i < params.numGenericRequirements; i++) {
                    let ptr = Memory.readPointer(this._ptr.add(offset));
                    if (ptr.isNull())
                        args.push(null)
                    else
                        args.push(new TargetMetadata(ptr));
                    offset += Process.pointerSize;
                }
            }
            return args;
        },
        enumerable: true,
    },
    getNominalTypeDescriptor: {
        value() {
            if (this.description.isNull())
                return null;
            return new TargetNominalTypeDescriptor(this.description);
        },
        enumerable: true,
    },
});
function TargetEnumMetadata(pointer) {
    this._ptr = pointer;

    switch (this.kind) {
        case "Enum":
        case "Optional":
            break;
        default:
            throw new Error("type is not an enum type");
    }
}
TargetEnumMetadata.prototype = Object.create(TargetValueMetadata.prototype, {
    getPayloadSize: {
        value(nominalType) {
            if (!nominalType.enum_.hasPayloadSizeOffset())
                return ptr(0);

            return Memory.readPointer(this._ptr.add(nominalType.enum_.getPayloadSizeOffset() * Process.pointerSize));
        },
        enumerable: true,
    },
});


function TargetGenericMetadata(ptr) {
    this._ptr = ptr;
}
TargetGenericMetadata.prototype = {
    // offset 0
    get createFunction() {
        return new NativeFunction(Memory.readPointer(this._ptr.add(0)), 'pointer', ['pointer', 'pointer']);
    },

    // offset 0+pointerSize
    get metadataSize() {
        return Memory.readU32(this._ptr.add(0 + Process.pointerSize));
    },

    // offset 4+pointerSize
    get numKeyArguments() {
        return Memory.readU16(this._ptr.add(4 + Process.pointerSize));
    },

    // offset 6+pointerSize
    get addressPoint() {
        return Memory.readU16(this._ptr.add(6 + Process.pointerSize));
    },

    // offset 8+pointerSize
    get privateData() {
        return Memory.readByteArray(this._ptr.add(8 + Process.pointerSize), 16*Process.pointerSize);
    },

    getMetadataTemplate() {
        return this._ptr.add(8 + 17 * Process.pointerSize);
    },

    _getMetadata() {
        return new TargetMetadata(this.getMetadataTemplate().add(this.addressPoint));
    },

    getTemplateDescription() {
        let metadata = new TargetMetadata(this.getMetadataTemplate().add(this.addressPoint));
        return metadata.getNominalTypeDescriptor();
    },
};
function TargetTupleTypeMetadata(pointer) {
    this._ptr = pointer;

    if (this.kind != "Tuple")
        throw new Error("type is not a tuple type");
}
TargetTupleTypeMetadata.prototype = Object.create(TargetMetadata.prototype, {
    // offset pointerSize
    numElements: {
        get() {
            return uint64(Memory.readPointer(this._ptr.add(Process.pointerSize)).toString());
        },
        enumerable: true,
    },
    // offset 2*pointerSize
    labels: {
        get() {
            return Memory.readPointer(this._ptr.add(2*Process.pointerSize));
        },
        enumerable: true,
    },
    // offset 3*pointerSize
    elements: {
        get() {
            let elems = [];
            const sizeOfTupleElement = 2 * Process.pointerSize;
            for (let i = 0; i < this.numElements; i++) {
                elems.push(new TupleElement(this._ptr.add(3*Process.pointerSize + (i * sizeOfTupleElement))));
            }
            return elems;
        },
        enumerable: true,
    },
});
function TupleElement(pointer) {
    this._ptr = pointer;
}
TupleElement.prototype = {
    // offset 0
    get type() {
        return new TargetMetadata(Memory.readPointer(this._ptr));
    },
    // offset pointerSize
    get offset() {
        return Memory.readPointer(this._ptr.add(Process.pointerSize)).toInt32();
    },
};
function TargetFunctionTypeMetadata(pointer) {
    this._ptr = pointer;

    if (this.kind != "Function")
        throw new Error("type is not a function type");
}
TargetFunctionTypeMetadata.prototype = Object.create(TargetMetadata.prototype, {
    // offset pointerSize
    flags: {
        get() {
            let val = Memory.readPointer(this._ptr.add(Process.pointerSize));
            return {
                numArguments: val.and(TargetFunctionTypeFlags.NumArgumentsMask).toInt32(),
                convention: val.and(TargetFunctionTypeFlags.ConventionMask).shr(TargetFunctionTypeFlags.ConventionShift).toInt32(),
                doesThrow: !val.and(TargetFunctionTypeFlags.ThrowsMask).isNull(),
            };
        },
        enumerable: true,
    },
    // offset 2*pointerSize
    resultType: {
        get() {
            return new TargetMetadata(Memory.readPointer(this._ptr.add(2*Process.pointerSize)));
        },
        enumerable: true,
    },
    // offset 3*pointerSize
    getArguments: {
        value: function() {
            let count = this.flags.numArguments;
            let args = [];
            let ptr = this._ptr.add(3 * Process.pointerSize);
            for (let i = 0; i < count; i++) {
                let arg = new Argument(Memory.readPointer(ptr.add(i * Process.pointerSize)));
                args.push({
                    inout: arg.flag,
                    type: arg.pointer,
                });
            }
            return args;
        },
        enumerable: true,
    },
});
const ForeginTypeMetadataFlags = {
    HasInitializationFunction: 1,
};
function TargetForeignTypeMetadata(pointer) {
    this._ptr = pointer;

    if (this.kind != "ForeignClass")
        throw new Error("type is not a foreign class type");
}
TargetForeignTypeMetadata.prototype = Object.create(TargetMetadata.prototype, {
    // offset -2 * pointerSize
    flags: {
        get() {
            return flagsToObject(ForeginTypeMetadataFlags, Memory.readPointer(this._ptr.sub(2*Process.pointerSize)));
        },
        enumerable: true,
    },
    // offset -3 * pointerSize
    unique: {
        get() {
            return Memory.readPointer(this._ptr.sub(3*Process.pointerSize));
        },
        enumerable: true,
    },
    // offset -4*pointerSize
    name: {
        get() {
            return Memory.readUtf8String(Memory.readPointer(this._ptr.sub(4*Process.pointerSize)));
        },
        enumerable: true,
    },
    // offset -5*pointerSize
    initializationFunction: {
        get() {
            return new NativeFunction(Memory.readPointer(this._ptr.sub(5 * Process.pointerSize)), 'void', ['pointer']);
        },
        enumerable: true,
    },
});
function TargetObjCClassWrapperMetadata(pointer) {
    this._ptr = pointer;

    if (this.kind !== "ObjCClassWrapper")
        throw new Error("type is not a ObjC class wrapper type");
}
TargetObjCClassWrapperMetadata.prototype = Object.create(TargetMetadata.prototype, {
    // offset pointerSize
    class_: {
        get() {
            return Memory.readPointer(this._ptr.add(Process.pointerSize));
        },
        enumerable: true,
    },
});
function ExistentialTypeFlags(val) {
    this._val = val;
}
ExistentialTypeFlags.prototype = {
    NumWitnessTablesMask: 0x00FFFFFF,
    ClassConstraintMask: 0x80000000,
    HasSuperclassMask: 0x40000000,
    SpecialProtocolMask: 0x3F000000,
    SpecialProtocolShift: 24,

    getNumWitnessTables() {
        return this._val & this.NumWitnessTablesMask;
    },
    getClassConstraint() {
        return !!(this._val & this.ClassConstraintMask) ? "Any" : "Class";
    },
    hasSuperclassConstraint() {
        return !!(this._val & this.HasSuperclassMask);
    },
    getSpecialProtocol() {
        const SpecialProtocol = [ "None", "Error" ];
        return SpecialProtocol[(this._val & this.SpecialProtocolMask) >> this.SpecialProtocolShift];
    },
};
function TargetExistentialTypeMetadata(pointer) {
    this._ptr = pointer;

    if (this.kind != "Existential")
        throw new Error("type is not a existential type");
}
TargetExistentialTypeMetadata.prototype = Object.create(TargetMetadata.prototype, {
    // offset pointerSize
    flags: {
        get() {
            return new ExistentialTypeFlags(Memory.readPointer(this._ptr.add(Process.pointerSize)));
        },
        enumerable: true,
    },
    // offset 2*pointerSize
    protocols: {
        get() {
            return new TargetProtocolDescriptorList(this._ptr.add(2*Process.pointerSize));
        },
        enumerable: true,
    },

    getRepresentation: {
        value() {
            // Some existentials use special containers.
            switch (this.flags.getSpecialProtocol()) {
                case "Error":
                    return "Error";
                case "None":
                    break;
            }
            // The layout of standard containers depends on whether the existential is
            // class-constrained.
            if (this.isClassBounded())
                return "Class";
            return "Opaque";
        },
        enumerable: true,
    },
    isObjC: {
        value() {
            return this.isClassBounded() && this.flags.getNumWitnessTables() == 0;
        },
        enumerable: true,
    },
    isClassBounded: {
        value() {
            return this.flags.getClassConstraint() == "Class";
        },
        enumerable: true,
    },
    getSuperclassConstraint: {
        value() {
            if (!this.flags.hasSuperclassConstraint())
                return null;

            // Get a pointer to tail-allocated storage for this metadata record.
            // The superclass immediately follows the list of protocol descriptors.
            let ptr = this._ptr.add(Process.pointerSize * (3 + this.protocols.numProtocols));

            return new TargetMetadata(Memory.readPointer(ptr));
        },
        enumerable: true,
    },
    /*mayTakeValue*/
    /*deinitExistentialContainer*/
    /*projectValue*/
    /*getDynamicType*/
    /*getWitnessTable*/
});

function TargetProtocolDescriptorList(pointer) {
    this._ptr = pointer;
}
TargetProtocolDescriptorList.prototype = {
    // offset 0
    get numProtocols() {
        return Memory.readPointer(this._ptr).toInt32();
    },
    // offset pointerSize
    get protocols() {
        let res = [];
        let numProtocols = this.numProtocols;
        for (let i = 0; i < numProtocols; i++) {
            res.push(new TargetProtocolDescriptor(Memory.readPointer(this._ptr.add((i + 1) * Process.pointerSize))));
        }
        return res;
    }
}
function TargetProtocolDescriptor(pointer) {
    this._ptr = pointer;
}
TargetProtocolDescriptor.prototype = {
    // offset 0
    get _ObjC_Isa() {
        return Memory.readPointer(this._ptr.add(0));
    },
    // offset pointerSize
    get name() {
        return Memory.readUtf8String(Memory.readPointer(this._ptr.add(Process.pointerSize)));
    },
    // offset 2*pointerSize
    get inheritedProtocols() {
        return new TargetProtocolDescriptorList(Memory.readPointer(this._ptr.add(2 * Process.pointerSize)));
    },

    // .. some more fields
};

const TargetFunctionTypeFlags = {
    NumArgumentsMask: 0x00FFFFFF,
    ConventionMask: 0x0F000000,
    ConventionShift: 24,
    ThrowsMask: 0x10000000,
};
const FunctionMetadataConvention = {
    Swift: 0,
    Block: 1,
    Thin: 2,
    CFunctionPointer: 3,
};

function RelativeIndirectablePointer(addr) {
    let relativeOffsetPlusIndirect = Memory.readS32(addr);
    let offset = relativeOffsetPlusIndirect & (~1);

    let val = addr.add(offset);
    if ((relativeOffsetPlusIndirect & 1) === 0) { // direct reference
        return val;
    } else { // indirect reference
        return Memory.readPointer(val);
    }
}
function ConstTargetFarRelativeDirectPointer(ptr) {
    let offset = Memory.readPointer(ptr);
    return ptr.add(offset);
}
function TargetRelativeDirectPointerRuntime(ptr) {
    let offset = Memory.readS32(ptr);
    return ptr.add(offset);
}
const GenericParameterDescriptorFlags = {
    HasParent: 1,
    HasGenericParent: 2,
};
function TargetNominalTypeDescriptor(ptr) {
    this._ptr = ptr;
}
TargetNominalTypeDescriptor.prototype = {
    // offset 0
    get mangledName() {
        let addr = TargetRelativeDirectPointerRuntime(this._ptr);
        return mangling.MANGLING_PREFIX + Memory.readUtf8String(addr);
    },
    // offset 4
    get clas() {
        let ptr = this._ptr.add(4);
        return {
            _ptr: ptr,

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
                return this.fieldOffsetVectorOffset !== 0;
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
                return this.getPayloadSizeOffset() !== 0;
            },
        };
    },


    // offset 20
    get genericMetadataPatternAndKind() {
        return RelativeDirectPointerIntPair(this._ptr.add(20));
    },

    // offset 24
    get accessFunction() {
        return TargetRelativeDirectPointerRuntime(this._ptr.add(24));
    },

    getGenericMetadataPattern() {
        return new TargetGenericMetadata(this.genericMetadataPatternAndKind.pointer);
    },

    getKind() {
        return NominalTypeKind[this.genericMetadataPatternAndKind.intVal];
    },

    offsetToNameOffset() {
        return 0;
    },

    // offset 28
    get genericParams() {
        let ptr = this._ptr.add(28);
        return {
            // offset 0
            get offset() {
                if (!this.isGeneric())
                    throw new Error("not generic!");
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
                return flagsToObject(GenericParameterDescriptorFlags, Memory.readU32(ptr.add(12)));
            },

            hasGenericRequirements() {
                return this.numGenericRequirements > 0;
            },

            isGeneric() {
                return this.hasGenericRequirements() || this.flags.HasGenericParent;
            },
        };
    },

    toString() {
        return "[TargetNominalType@" + this._ptr + ": " + this.mangledName + "]";
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
                throw new Error("not direct type metadata");

            default:
                throw new Error("invalid type kind");
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
                throw new Error("not generic metadata pattern");

            default:
                throw new Error("invalid type kind");
        }

        return new TargetNominalTypeDescriptor(this._typeDescriptor);
    },

    getCanonicalTypeMetadata(api) { // returns a Metadata* for non-generic types
        let res = null;
        switch (this.getTypeKind()) {
            case TypeMetadataRecordKind.UniqueDirectType:
                res = this.getDirectType();
                break;
            case TypeMetadataRecordKind.NonuniqueDirectType:
                res = api.swift_getForeignTypeMetadata(this.getDirectType());
                break;
            case TypeMetadataRecordKind.UniqueDirectClass:
                let directType = this.getDirectType();
                if (directType) {
                    res = api.swift_getObjCClassMetadata(directType);
                }
                break;
            default:
                break;
        }
        return res === null ? null : new TargetMetadata(res);
    },
}

function OpaqueExistentialContainer(pointer) {
    this._ptr = pointer;
}
OpaqueExistentialContainer.prototype = {
    // offset 0
    get fixedSizeBuffer() {
        return [
            Memory.readPointer(this._ptr.add(0)),
            Memory.readPointer(this._ptr.add(Process.pointerSize)),
            Memory.readPointer(this._ptr.add(2*Process.pointerSize)),
        ];
    },
    // class types have a pointer in the fixedSizeBuffer
    get heapObject() {
        return new HeapObject(this.fixedSizeBuffer[0]);
    },
    // offset 3*pointerSize
    get type() {
        return new TargetMetadata(Memory.readPointer(this._ptr.add(3*Process.pointerSize)));
    },
    // offset 4*pointerSize
    getWitnessTable(index) {
        return Memory.readPointer(this._ptr.add((4 + index) * Process.pointerSize));
    },
};
function ClassExistentialContainer(pointer) {
    this._ptr = pointer;
}
ClassExistentialContainer.prototype = {
    // offset 0
    get heapObject() {
        return new HeapObject(Memory.readPointer(this._ptr.add(0)));
    },
    // offset pointerSize
    getWitnessTable(index) {
        return Memory.readPointer(this._ptr.add((1 + index) * Process.pointerSize));
    },
};

function HeapObject(pointer) {
    this._ptr = pointer;
}
HeapObject.prototype = {
    // offset 0
    get heapMetadata() {
        return new TargetMetadata(Memory.readPointer(this._ptr.add(0)));
    },
    // TODO: reference count stuff
};

const ProtocolClassConstraint = {
    Class: 0,
    Any: 1,
};

module.exports = {
    TargetMetadata: TargetMetadata,
    TargetClassMetadata: TargetClassMetadata,
    TargetProtocolConformanceRecord: TargetProtocolConformanceRecord,
    TargetTypeMetadataRecord: TargetTypeMetadataRecord,
    TargetNominalTypeDescriptor: TargetNominalTypeDescriptor,
    TargetFunctionTypeFlags: TargetFunctionTypeFlags,
    NominalTypeKind: NominalTypeKind,
    TypeMetadataRecordKind: TypeMetadataRecordKind,
    FieldTypeFlags: FieldTypeFlags,
    FunctionMetadataConvention: FunctionMetadataConvention,
    MetadataKind: MetadataKind,
    OpaqueExistentialContainer: OpaqueExistentialContainer,
    ClassExistentialContainer: ClassExistentialContainer,
    ProtocolClassConstraint: ProtocolClassConstraint,
};
