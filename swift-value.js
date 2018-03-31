const types = require('./types');

let selfPointers = new Map();
// We need to hook this function at startup, because hooking it seems to happen asynchronously
// (maybe because this is basically self-modifying code?) and we don't want to run into race-conditions.
let toCStringPtr = Module.findExportByName("libswiftFoundation.dylib", "_T0s14StringProtocolP10FoundationsAARzSS5IndexVADRtzlE01cA0Says4Int8VGSgSSACE8EncodingV5using_tF");
Interceptor.attach(toCStringPtr, {
    onEnter: function() {
        if (selfPointers.has(this.threadId)) {
            let selfRegister = Process.pointerSize === 8 ? "x20" : "r10";
            this.context[selfRegister] = selfPointers.get(this.threadId);
            selfPointers.delete(this.threadId)
        }
    },
});

function swiftToString(obj) {
    let type = obj.$type;
    let pointer = obj.$pointer;
    /*
     * built by disassembling the code for this snippet:
     *
        var str = String()
        dump(x, to: &str)
        let arr : [CChar] = str.cString(using: String.Encoding.utf8)!
        let ptr = UnsafePointer<CChar>(arr)
        strlen(ptr)
     */
    function __swift_destroy_boxed_opaque_existential_0(pointer) {
        let opaque = new types.OpaqueExistentialContainer(pointer);
        let type = opaque.type;
        let vwt = opaque.type.valueWitnessTable;
        if (vwt.flags.IsNonInline) {
            let _swift_release_ = new NativeFunction(Memory.readPointer(Swift._api._swift_release), 'void', ['pointer']);
            _swift_release_(opaque.fixedSizeBuffer[0]);
        } else {
            let destroy = vwt.destroy;
            destroy(pointer, type._ptr);
        }
    }

    let SwiftString = Swift._typesByName.get("Swift.String");
    if (!SwiftString.canonicalType)
        SwiftString = SwiftString.withGenericParams();

    let dynamicType;

    let copy = Memory.alloc(4 * Process.pointerSize);
    let copyFn;
    if (type.kind === "Existential" && type.getRepresentation() === "Opaque") {
        dynamicType = Swift._api.swift_getDynamicType(pointer, type.canonicalType._ptr, 1);
        copyFn = type.canonicalType.valueWitnessTable.initializeBufferWithCopyOfBuffer;
    } else {
        dynamicType = type.canonicalType._ptr;
        copyFn = type.canonicalType.valueWitnessTable.initializeBufferWithCopy;
    }
    copyFn(copy, pointer, dynamicType);
    Memory.writePointer(copy.add(3 * Process.pointerSize), dynamicType);

    let stringResult = Memory.alloc(Process.pointerSize * 3);
    Memory.writePointer(stringResult, Swift._api._T0s19_emptyStringStorages6UInt32Vv);
    Memory.writePointer(stringResult.add(Process.pointerSize), ptr(0));
    Memory.writePointer(stringResult.add(2*Process.pointerSize), ptr(0));


    let textOutputStreamWitnessTableForString = Swift._api._T0SSs16TextOutputStreamsWP;
    let Any = Swift._api.swift_getExistentialTypeMetadata(1, ptr(0), 0, ptr(0));

    let dump = Swift._api._T0s4dumpxx_q_z2toSSSg4nameSi6indentSi8maxDepthSi0E5Itemsts16TextOutputStreamR_r0_lF;

    const LONG_MAX = ptr(0).not().shr(1);

    // TODO: default arguments should in theory be retrieved via generator functions
    let res = dump(/*value*/ copy,
        /*to*/ stringResult,
        /*name*/ ptr(0), ptr(0), ptr(0), 1,
        /*indent*/ ptr(0),
        /*maxDepth*/ LONG_MAX,
        /*maxItems*/ LONG_MAX,
        /*static type of `value`*/ Any,
        /*static type of `to`*/ SwiftString.canonicalType._ptr,
        /*how to use `to` as a TextOutputStream*/ textOutputStreamWitnessTableForString);

    // We really should be calling ___swift_destroy_boxed_opaque_existential_0  on res
    // but Frida already has deconstructed it into a struct for us.
    // But we know that `dump` just returns a pointer to the container the `copy` parameter points to --
    // so let's just destroy that.
    __swift_destroy_boxed_opaque_existential_0(copy);

    let encoding = Memory.readPointer(Swift._api._T0SS10FoundationE8EncodingV4utf8ACfau());

    let witnessTableStringProtocol = Swift._api._T0SSs14StringProtocolsWP;
    let listener;
    let threadId = Process.getCurrentThreadId();
    let toCString = new NativeFunction(toCStringPtr, 'pointer', ['pointer', 'pointer', 'pointer']);
    selfPointers.set(threadId, stringResult);
    let array = toCString(encoding, SwiftString.canonicalType._ptr, witnessTableStringProtocol);

    // the `BridgeObject` this `[CChar]?` contains somewhere deep down is Opaque, so we can't use type
    // metadata to find this offset
    let str = Memory.readUtf8String(array.add(8 + 3 * Process.pointerSize));

    Swift._api.swift_unknownRelease(Memory.readPointer(stringResult.add(2*Process.pointerSize)));
    Swift._api.swift_bridgeObjectRelease(array);

    return str;
}

function isClassType(t) {
    return t.kind === "Class" || (t.kind === "Existential" && t.getRepresentation() === "Class");
}

function makeWrapper(type, pointer, owned) {
    let staticType = type;
    if ("$kind" in type) { // an ObjC type
        console.log("making ObjC object");
        return ObjC.Object(Memory.readPointer(pointer));
    }

    let wrapperObject = {};
    if (type.kind === "Function") {
        wrapperObject = function(...argList) {
            if (type.kind !== "Function")
                throw TypeError("this value has a non-function type, so it cannot be called");

            let flags = type.functionFlags;
            if (argList.length < flags.numArguments) {
                throw TypeError("missing arguments: " + flags.numArguments + " arguments required");
            } else if (argList.length > flags.numArguments) {
                throw TypeError("too many arguments: " + flags.numArguments + " arguments required");
            }

            if (flags.doesThrow) {
                throw Error("calling a function that can throw is not yet supported"); // TODO
            }

            switch (flags.convention) {
                case types.FunctionMetadataConvention.Swift:
                    throw Error("calling Swift functions not yet supported");
                case types.FunctionMetadataConvention.Block: {
                    let block = new ObjC.Block(pointer);
                    return block.implementation(...params);
                }
                case types.FunctionMetadataConvention.Thin:
                    throw Error("calling thin functions not yet supported");
                case types.FunctionMetadataConvention.CFunctionPointer: {
                    let params = [];
                    let fridaTypes = [];
                    let argTypes = type.getArguments();

                    function convertType(swiftType, swiftOrJSVal) {
                        let fridaType, jsVal;
                        jsVal = ("toJS" in argType) ? argType.toJS(swiftOrJSVal.$pointer) : swiftOrJSVal;
                        switch (argType.toString()) {
                            case "Builtin.Int8":
                            case "Swift.Int8":
                                fridaType = "int8";
                                break;
                            case "Builtin.UInt8":
                            case "Swift.UInt8":
                                fridaType = "uint8";
                                break;
                            case "Builtin.Int16":
                            case "Swift.Int16":
                                fridaType = "int16";
                                break;
                            case "Builtin.UInt16":
                            case "Swift.UInt16":
                                fridaType = "uint16";
                                break;
                            case "Builtin.Int32":
                            case "Swift.Int32":
                                fridaType = "int32";
                                break;
                            case "Builtin.UInt32":
                            case "Swift.UInt32":
                                fridaType = "uint32";
                                break;
                            case "Builtin.Int64":
                            case "Swift.Int64":
                                fridaType = "int64";
                                break;
                            case "Builtin.UInt64":
                            case "Swift.UInt64":
                                fridaType = "uint64";
                                break;
                            case "Swift.Double":
                                fridaType = "double";
                                break;
                            case "Swift.Float":
                                fridaType = "float";
                                break;
                            case "()":
                                fridaType = "void";
                                jsVal = undefined;
                                break;
                            default:
                                if (argType.nominalType && argType.nominalType.mangledName === "_T0SP") {
                                    fridaType = "pointer";
                                    if (swiftOrJsVal instanceof NativePointer)
                                        jsVal = swiftOrJsVal;
                                    else if (jsVal !== undefined)
                                        jsVal = Memory.readPointer(swiftOrJsVal.$pointer);
                                } else {
                                    throw Error("don't know how to convert a '" + argType.toString() + "' to a C value!");
                                }
                        }

                        return { fridaType: fridaType, jsVal: jsVal };
                    }

                    for (let i = 0; i < flags.numArguments; i++) {
                        let res = convertType(argTypes[i], argList[i]);
                        if (res.jsVal === undefined && res.fridaType !== "void") {
                            throw Error("argument " + i + " must not be undefined");
                        }
                        fridaTypes.push(res.fridaType);
                        params.push(res.jsVal);
                    }

                    let returnType = convertType(type.returnType, undefined);
                    let func = new NativeFunction(Memory.readPointer(pointer), returnType, fridaTypes);
                    return func(...params);
                }
            }
        };
    } else if (isClassType(type)) {
        Object.defineProperties(wrapperObject, {
            '$isa': {
                enumerable: true,
                get() {
                    let object = Memory.readPointer(pointer);
                    return Memory.readPointer(object.add(0));
                },
            },
            '$retainCounts': {
                enumerable: true,
                get() {
                    let object = Memory.readPointer(pointer);
                    return Swift._api.CFGetRetainCount(object);
                },
            },
        });
        let object = Memory.readPointer(pointer);
        let canonical = ObjC.api.object_getClass(object);
        type = Swift._typeFromCanonical(canonical);
    }

    wrapperObject.$staticType = staticType;
    wrapperObject.$type = type;
    wrapperObject.$pointer = pointer;

    wrapperObject.toString = swiftToString.bind(undefined, wrapperObject);

    if ('enumCases' in type) {
        let enumCases = type.enumCases();
        if (enumCases.length === 1) {
            wrapperObject.$enumCase = 0;
        } else if (enumCases.length !== 0) {
            let numPayloads = type.nominalType.enum_.getNumPayloadCases();
            Object.defineProperty(wrapperObject, '$enumCase', {
                enumerable: true,
                get() {
                    let tag;
                    if (numPayloads === 0) {
                        // a C-like enum: an integer just large enough to represent all cases
                        if (enumCases.length < (1 << 8))
                            tag = Memory.readU8(pointer);
                        else if (enumCases.length < (1 << 16))
                            tag = Memory.readU16(pointer);
                        else if (enumCases.length < (1 << 32))
                            tag = Memory.readU32(pointer);
                        else if (enumCases.length < (1 << 64))
                            tag = Memory.readU64(pointer);
                        else
                            throw Error("impossibly large number of enum cases");
                    } else if (numPayloads === 1) {
                        // single-payload enum: tag is after the value, or in spare bits if available
                        let opaqueVal = pointer;
                        let payloadType = enumCases[0].type.canonicalType._ptr;
                        tag = Swift._api.swift_getEnumCaseSinglePayload(opaqueVal, payloadType, enumCases.length - numPayloads);
                    } else {
                        // multi-payload enum:
                        // - all non-payload cases are collapsed into a single tag, secondary tag to
                        //   differentiate them is stored in place of value
                        // - tag is stored in spare bits shared by all values
                        // - all remaining bits of tag (that don't fit in spare bits) are appended to the value
                        let opaqueVal = pointer;
                        tag = Swift._api.swift_getEnumCaseMultiPayload(opaqueVal, type.nominalType._ptr);
                    }
                    // tag is in range [-ElementsWithPayload..ElementsWithNoPayload-1]
                    // but we want an index into the array returned by enumCases()
                    return tag + numPayloads;
                },
            });
            if (numPayloads > 0) {
                Object.defineProperty(wrapperObject, '$enumPayloadCopy', {
                    enumerable: true,
                    value() {
                        let curCase = enumCases[this.$enumCase];
                        if (curCase.type === null)
                            return undefined;

                        let enumVwt = type.canonicalType.valueWitnessTable;
                        let payloadVwt = curCase.type.canonicalType.valueWitnessTable;
                        enumVwt.destructiveProjectEnumData(pointer, type.canonicalType._ptr);

                        let payload = Memory.alloc(payloadVwt.size.toInt32());
                        let address = curCase.indirect ? Swift._api.swift_projectBox(pointer) : pointer;
                        payloadVwt.initializeWithCopy(payload, pointer, curCase.type.canonicalType._ptr);

                        enumVwt.destructiveInjectEnumTag(pointer, curCase.tag, type.canonicalType._ptr);

                        // TODO: document that user needs to free this memory
                        return makeWrapper(curCase.type, payload, true);
                    },
                });
            }
        }
    }

    if ("fields" in type) {
        for (let field of type.fields()) {
            let getAddr = function getAddr() {
                let addr;
                if (type.kind === "Struct") {
                    addr = pointer.add(field.offset);
                } else { // Class
                    let object = Memory.readPointer(pointer);
                    addr = object.add(field.offset);
                }
                return addr;
            };

            Object.defineProperty(wrapperObject, field.name, {
                enumerable: true,
                get() {
                    let addr = getAddr();
                    let pointer = addr;
                    if (field.weak) {
                        let strong = Swift._api.swift_weakLoadStrong(addr);
                        if (strong.isNull())
                            return null;
                        // weakLoadStrong() just incremented the strong reference count, undo that.
                        // If the user wants to keep this alive longer than right now, they need to manually increase
                        // the reference count for such a variable for anything else, too.
                        Swift._api.swift_release(strong);
                        pointer = strong;
                    }

                    if ("toJS" in field.type) {
                        let val = field.type.toJS(pointer);
                        if (val !== undefined)
                            return val;
                    }
                    return new field.type(pointer);
                },
                set(newVal) {
                    let addr = getAddr();
                    if (field.weak) {
                        Swift._api.swift_weakAssign(addr, newVal.$pointer);
                    } else {
                        let assigned = false;
                        if ("fromJS" in field.type && !("$pointer" in newVal))
                            assigned = field.type.fromJS(pointer, newVal);
                        if (!assigned) {
                            type.valueWitnessTable.assignWithCopy(addr, newVal.$pointer, newVal.$type.canonicalType._ptr);
                        }
                    }
                },
            });
        }
    }

    if (type.kind === "Existential") {
        Object.defineProperty(wrapperObject, '$wrappedType', {
            enumerable: true,
            get() {
                if (type.getRepresentation() === "Opaque") {
                    let cont = new types.OpaqueExistentialContainer(pointer);
                    return cont.$type;
                }
                throw Error("not yet implemented");
            },
        });
    }

    if ("tupleElements" in type) {
        let cnt = 0;
        for (let elem of type.tupleElements()) {
            let label = elem.label;
            let curCnt = cnt;
            if (label !== null) {
                Object.defineProperty(wrapperObject, label, {
                    enumerable: true,
                    get() { return wrapperObject[curCnt]; },
                });
            }
            Object.defineProperty(wrapperObject, cnt.toString(), {
                enumerable: true,
                get() {
                    return elem.type(pointer.add(elem.offset));
                },
            });
            cnt++;
        }
    }
    let destroyWrapper = function() {
            Object.keys(wrapperObject).forEach(key => Reflect.deleteProperty(wrapperObject, key));
            pointer = undefined;
            type = undefined;
    };
    if (owned) {
        wrapperObject.$destroy = function() {
            type.canonicalType.valueWitnessTable.destroy(pointer, type.canonicalType._ptr);
            destroyWrapper();
        };
    }
    wrapperObject.$assignWithCopy = function(val) {
        if ("$kind" in val) { // ObjC type
            throw Error("ObjC types not yet supported");
        } else if ("fromJS" in type) {
            type.fromJS(pointer, val);
            return this;
        } else {
            staticType.canonicalType.valueWitnessTable.assignWithCopy(pointer, val.$pointer, staticType.canonicalType);
            let newWrapper = makeWrapper(pointer, val.$type);
            destroyWrapper();
            return newWrapper;
        }
    };

    Object.preventExtensions(wrapperObject);

    return wrapperObject;
}

function makeSwiftValue(type) {
    if (!type.canonicalType) {
        throw Error("the type of a value must have a canonical type descriptor!");
    }

    let SwiftValue = function (pointer) {
        return makeWrapper(type, pointer);
    };
    Reflect.defineProperty(SwiftValue, 'name', { value: type.toString() });

    return SwiftValue;
}

module.exports = {
    makeSwiftValue: makeSwiftValue,
};
