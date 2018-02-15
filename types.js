"use strict";

/* jshint esnext: true, evil: true */

// for all these definitions, look at include/swift/Runtime/Metadata.h and friends in the Swift sources
// based on commit 2035c311736d15c9ef1a7e2e42a925a6ddae098c

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
        return new TargetClassMetadata(this.directType);
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
                return api.swift_getForeignTypeMetadata(this.getDirectType());
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
        if (classMetadata !== null && !ptr(0).equals(classMetadata))
            return api.swift_getObjCClassMetadata(classMetadata);
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
function TargetClassMetadata(ptr) {
    this._ptr = ptr;
}
TargetClassMetadata.prototype = {
    // offset -2 * pointerSize
    get destructor() {
        return Memory.readPointer(this._ptr.sub(2 * Process.pointerSize));
    },
    // offset -pointerSize
    get valueWitnessTable() {
        return Memory.readPointer(this._ptr.sub(Process.pointerSize));
    },

    // offset 0
    get isa() {
        let val = Memory.readPointer(this._ptr);
        if (val.compare(ptr(4096)) <= 0) {
            return null;
        }
        return val;
    },
    // offset pointerSize
    get superClass() {
        return new TargetMetadata(Memory.readPointer(this._ptr.add(Process.pointerSize)));
    },
    // offset 2*pointerSize
    get cacheData() {
        return [
            Memory.readPointer(this._ptr.add(2 * Process.pointerSize)),
            Memory.readPointer(this._ptr.add(3 * Process.pointerSize)),
        ];
    },
    // offset 4 * pointerSize
    get data() {
        return Memory.readPointer(this._ptr.add(4 * Process.pointerSize));
    },
    // offset 5 * pointerSize
    get flags() {
        return Memory.readU32(this._ptr.add(5 * Process.pointerSize));
    },
    // offset 5 * pointerSize + 4
    get instanceAddressPoint() {
        return Memory.readU32(this._ptr.add(4 + 5 * Process.pointerSize));
    },
    // offset 5 * pointerSize + 8
    get instanceSize() {
        return Memory.readU32(this._ptr.add(8 + 5 * Process.pointerSize));
    },
    // offset 5 * pointerSize + 12
    get instanceAlignMask() {
        return Memory.readU16(this._ptr.add(12 + 5 * Process.pointerSize));
    },
    // offset 5 * pointerSize + 14: reserved
    // offset 5 * pointerSize + 16
    get classSize() {
        return Memory.readU32(this._ptr.add(16 + 5 * Process.pointerSize));
    },
    // offset 5 * pointerSize + 20
    get classAddressPoint() {
        return Memory.readU32(this._ptr.add(20 + 5 * Process.pointerSize));
    },
    // offset 5 * pointerSize + 24
    get description() {
        return ConstTargetFarRelativeDirectPointer(this._ptr.add(24 + 5 * Process.pointerSize));
    },
    // offset 6 * pointerSize + 24
    get iVarDestroyer() {
        return new NativePointer(Memory.readPointer(this._ptr.add(24 + 6 * Process.pointerSize)), 'void', ['pointer']);
    },

    isTypeMetadata() {
        return this.data.and(ptr(1)).equals(ptr(1));
    },
    isArtificialSubclass() {
        if(!this.isTypeMetadata())
            throw Error("assertion error");
        return this.description.compare(int64(0)) === 0;
    },
    getDescription() {
        if(!this.isTypeMetadata())
            throw Error("assertion error");
        if(this.isArtificialSubclass())
            throw Error("assertion error");
        return this.description;
    },
};
function TargetValueMetadata(ptr) {
    this._ptr = ptr;
}
TargetValueMetadata.prototype = {
    // offset pointerSize
    get description() {
        let val = ConstTargetFarRelativeDirectPointer(this._ptr.add(Process.pointerSize));
        if (val.equals(ptr(0)))
            return null;
        return val;
    },
};

function TargetMetadata(ptr) {
    this._ptr = ptr;
}
if ("_debug" in global)
    global.TargetClassMetadata = TargetClassMetadata;
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
};


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
    get name() {
        let addr = TargetRelativeDirectPointerRuntime(this._ptr);
        return Memory.readCString(addr);
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
                return this.hasGenericRequirements() || (this.flags & GenericParameterDescriptorFlags.HasGenericParent) !== 0;
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
    TargetClassMetadata: TargetClassMetadata,
    TargetProtocolConformanceRecord: TargetProtocolConformanceRecord,
    TargetTypeMetadataRecord: TargetTypeMetadataRecord,
};
