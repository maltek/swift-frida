"use strict";

/* jshint esnext: true, evil: true */

const mangling = require('./mangling');

// for all these definitions, look at include/swift/Runtime/Metadata.h and friends in the Swift sources
// based on commit 2035c311736d15c9ef1a7e2e42a925a6ddae098c

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
        return Memory.readPointer(this._ptr.add(Process.pointerSize));
    },
    // offset 2* pointerSize
    get stride() {
        return Memory.readPointer(this._ptr.add(2 * Process.pointerSize));
    },
    // offset 3* pointerSize
    get extraInhabitantFlags() {
        if (this.flags.and(ValueWitnessFlags.HasExtraInhabitants).isNull())
            throw Error("extra inhabitant flags not available");
        return Memory.readPointer(this._ptr.add(3 * Process.pointerSize));
    },
};
function ValueWitnessTable(pointer) {
    TypeLayout.call(this, pointer.add(17 * Process.pointerSize));
    this._vwt = pointer;
}
ValueWitnessTable.prototype = Object.create(TypeLayout.prototype, {
    isValueInline: {
        value: function(size, alignment) {
            if (size !== undefined && alignment !== undefined)
                return (size <= 3 * Process.pointerSize && alignment <= Process.pointerSize);
            else if (size !== undefined)
                throw Error("no overload with 1 argument");
            else
                return !(this.flags & ValueWitnessFlags.IsNonInline);
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
              throw Error("not direct type metadata");
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
              throw Error("not direct class object");
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
              throw Error("not indirect class object");
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
                throw Error("not generic metadata pattern");
		}

        return this.typeDescriptor;
	},

    /// Get the directly-referenced static witness table.
    getStaticWitnessTable() {
        switch (this.getConformanceKind()) {
            case ProtocolConformanceReferenceKind.WitnessTable:
                break;

            case ProtocolConformanceReferenceKind.WitnessTableAccessor:
                throw Error("not witness table");
        }
        return this.witnessTable;
    },

    getWitnessTableAccessor() {
        switch (this.getConformanceKind()) {
            case ProtocolConformanceReferenceKind.WitnessTableAccessor:
                break;

            case ProtocolConformanceReferenceKind.WitnessTable:
                throw Error("not witness table accessor");
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
    Class: 0,
    Struct: 1,
    Enum: 2,
    Optional: 3,
};

const MetadataKind = {
    Class: 0,
    Struct: 1,
    Enum: 2,
    Optional: 3,

    Opaque: 8,
    Tuple: 9,
    Function: 10,
    Existential: 12,
    Metatype: 13,
    ObjCClassWrapper: 14,
    ExistentialMetatype: 15,
    ForeignClass: 16,
    HeapLocalVariable: 64,
    HeapGenericLocalVariable: 65,
    ErrorObject: 128,
};

function TargetMetadata(pointer) {
    this._ptr = pointer;
    switch (this.kind) {
        case MetadataKind.Class:
            return new TargetClassMetadata(pointer);
        case MetadataKind.Struct:
        case MetadataKind.Enum:
        case MetadataKind.Optional:
            return new TargetValueMetadata(pointer);
        case MetadataKind.Tuple:
            return new TargetTupleTypeMetadata(pointer);
        case MetadataKind.Function:
            return new TargetFunctionTypeMetadata(pointer);
    }
}
TargetMetadata.prototype = {
    get kind() {
        let val = Memory.readPointer(this._ptr);
        if (val.compare(ptr(4096)) > 0) {
            return MetadataKind.Class;
        }
        return val.toInt32();
    },

    getNominalTypeDescriptor() {
        let val;
        switch (this.kind) {
            case MetadataKind.Class: {
                let cls = new TargetClassMetadata(this._ptr);
                if (!cls.isTypeMetadata()) {
                    return null;
                }
                if (cls.isArtificialSubclass()) {
                    return null;
                }
                val = cls.getDescription();
                break;
            }
            case MetadataKind.Struct:
            case MetadataKind.Enum:
            case MetadataKind.Optional:
                val = new TargetValueMetadata(this._ptr).description;
                break;
            default:
                return null;
        }
        return new TargetNominalTypeDescriptor(val);
    },

    toString() {
        let kind = Object.getOwnPropertyNames(MetadataKind).filter(k => MetadataKind[k] == this.kind)[0];
        return "[TargetMetadata: " + kind + "@" + this._ptr + "]";
    },
};
function TargetClassMetadata(pointer) {
    this._ptr = pointer;
    if (this.kind !== MetadataKind.Class)
        throw Error("type is not a class type");
}
if ("_debug" in global)
    global.TargetClassMetadata = TargetClassMetadata;
TargetClassMetadata.prototype = Object.create(TargetMetadata.prototype, {
    // offset -2 * pointerSize
    destructor: {
        get() {
            return Memory.readPointer(this._ptr.sub(2 * Process.pointerSize));
        },
        enumerable: true,
    },
    // offset -pointerSize
    valueWitnessTable: {
        get() {
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
            return new TargetClassMetadata(Memory.readPointer(this._ptr.add(Process.pointerSize)));
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
            return Memory.readU32(this._ptr.add(5 * Process.pointerSize));
        },
        enumerable: true,
    },
    // offset 5 * pointerSize + 4
    instanceAddressPoint: {
        get() {
            return Memory.readU32(this._ptr.add(4 + 5 * Process.pointerSize));
        },
        enumerable: true,
    },
    // offset 5 * pointerSize + 8
    instanceSize: {
        get() {
            return Memory.readU32(this._ptr.add(8 + 5 * Process.pointerSize));
        },
        enumerable: true,
    },
    // offset 5 * pointerSize + 12
    instanceAlignMask: {
        get() {
            return Memory.readU16(this._ptr.add(12 + 5 * Process.pointerSize));
        },
        enumerable: true,
    },
    // offset 5 * pointerSize + 14: reserved
    // offset 5 * pointerSize + 16
    classSize: {
        get() {
            return Memory.readU32(this._ptr.add(16 + 5 * Process.pointerSize));
        },
        enumerable: true,
    },
    // offset 5 * pointerSize + 20
    classAddressPoint: {
        get() {
            return Memory.readU32(this._ptr.add(20 + 5 * Process.pointerSize));
        },
        enumerable: true,
    },
    // offset 5 * pointerSize + 24
    description: {
        get() {
            return ConstTargetFarRelativeDirectPointer(this._ptr.add(24 + 5 * Process.pointerSize));
        },
        enumerable: true,
    },
    // offset 6 * pointerSize + 24
    iVarDestroyer: {
        get() {
            return new NativePointer(Memory.readPointer(this._ptr.add(24 + 6 * Process.pointerSize)), 'void', ['pointer']);
        },
        enumerable: true,
    },

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
            if(!this.isTypeMetadata())
                throw Error("assertion error");
            return this.description.compare(int64(0)) === 0;
        },
        enumerable: true,
    },
    getDescription: {
        value: function() {
            if(!this.isTypeMetadata())
                throw Error("assertion error");
            if(this.isArtificialSubclass())
                throw Error("assertion error");
            return this.description;
        },
        enumerable: true,
    },
    getNominalTypeDescriptor: {
        value: function() {
            if (this.isTypeMetadata() && !this.isArtificialSubclass())
                return new TargetNominalTypeDescriptor(this.getDescription());
            else
                return TargetMetadata.prototype.getNominalTypeDescriptor.call(this);
        },
        enumerable: true,
    },
});
function TargetValueMetadata(pointer) {
    this._ptr = pointer;

    switch (this.kind) {
        case MetadataKind.Struct:
        case MetadataKind.Enum:
        case MetadataKind.Optional:
            break;
        default:
            throw Error("type is not a value type");
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

    getTemplateDescription() {
        return MetadataKind.readFromMemory(this.getMetadataTemplate().add(this.addressPoint));
    },
};
function TargetTupleTypeMetadata(pointer) {
    this._ptr = pointer;

    if (this.kind != MetadataKind.Tuple)
        throw Error("type is not a tuple type");
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

    if (this.kind != MetadataKind.Function)
        throw Error("type is not a function type");
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
function TargetNominalTypeDescriptor(ptr) {
    this._ptr = ptr;
}
TargetNominalTypeDescriptor.prototype = {
    // offset 0
    get mangledName() {
        let addr = TargetRelativeDirectPointerRuntime(this._ptr);
        return mangling.MANGLING_PREFIX + Memory.readCString(addr);
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
            }
        };
    },


    // offset 16
    get genericMetadataPatternAndKind() {
        return RelativeDirectPointerIntPair(this._ptr.add(16));
    },

    // offset 20
    get accessFunction() {
        let args = [];
        // the type of this function depends on the generic requirements of this type
        for (let i = 0; i < this.genericParams.numGenericRequirements; i++) {
            args.push('pointer');
        }
        return new NativeFunction(TargetRelativeDirectPointerRuntime(this._ptr.add(21)), 'pointer', args);
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
    get genericParams() {
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
                return this.numGenericRequirements > 0;
            },

            isGeneric() {
                return this.hasGenericRequirements() || (this.flags & GenericParameterDescriptorFlags.HasGenericParent) !== 0;
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

module.exports = {
    TargetMetadata: TargetMetadata,
    TargetClassMetadata: TargetClassMetadata,
    TargetProtocolConformanceRecord: TargetProtocolConformanceRecord,
    TargetTypeMetadataRecord: TargetTypeMetadataRecord,
    MetadataKind: MetadataKind,
    NominalTypeKind: NominalTypeKind,
    TargetNominalTypeDescriptor: TargetNominalTypeDescriptor,
    TypeMetadataRecordKind: TypeMetadataRecordKind,
    FieldTypeFlags: FieldTypeFlags,
};
