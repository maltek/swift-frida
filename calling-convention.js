"use strict";

/* jshint esnext: true, evil: true */


let convention;
if (Process.arch === "arm64" && Process.platform === "darwin") {
    // see swift-llvm/lib/Target/AArch64/AArch64CallingConvention.td
    convention = {
        selfRegister: 'x20',
        errorRegister: 'x21',
        indirectResultRegister: 'x8',
        maxInlineArgument: 128,
        maxInlineReturn: 4 * Process.pointerSize, // see shouldPassIndirectlyForSwift in swift-llvm/lib/CodeGen/TargetInfo.cpp
        firstArgRegister: 'x0',
        maxVoluntaryInt: Process.pointerSize,
        maxInt: 8,
        maxIntAlignment: 8,
    };
} else if (Process.arch === "arm" && Process.platform === "darwin") {
    // see swift-llvm/lib/Target/ARM/ARMCallingConv.td
    convention = {
        selfRegister: 'r10',
        errorRegister: 'r8',
        indirectResultRegister: undefined, // first argument, not a special register
        maxInlineArgument: 64, // TODO: watchOS uses 128
        maxInlineReturn: 4 * Process.pointerSize, // see shouldPassIndirectlyForSwift in swift-llvm/lib/CodeGen/TargetInfo.cpp
        firstArgRegister: 'r0',
        maxVoluntaryInt: Process.pointerSize,
        maxInt: 8,
        maxIntAlignment: 4,
    };
} else {
    throw new Error("unknown platform");
}
//convention.freeze();

let errors = new Map();

let storeError = new NativeCallback(function storeError() {
    errors.set(Process.getCurrentThreadId(), callStack);
}, 'void', ['pointer']);
function checkTrampolineError() {
    let id = Process.getCurrentThreadId();
    let val = errors.get(id, callStack);
    errors.remove(id);
    return val;
}

function makeCallTrampoline(func, withError, self, indirectResult) {
    if (!withError && !self && !indirectResult)
        return {callAddr: func};

    let buf = Memory.alloc(Process.pageSize);
    let wr, blx;
    if (Process.arch === "arm64") {
        wr = new Arm64Writer(buf);
        blx = 'putBlImm';
    } else {
        wr = new ThumbWriter(buf);
        blx = 'putBlxImm';
    }

    if (withError)
        wr.putLdrRegAddress(convention.errorRegister, ptr(0));
    if (self)
        wr.putLdrRegAddress(convention.selfRegister, self);
    if (indirectResult) {
        if (!convention.indirectResultRegister)
            throw new Error("only provide the indirect result pointer on platforms with a specific register for it!");
        wr.putLdrRegAddress(convention.indirectResultRegister, indirectResult);
    }

    wr[blx](func);

    if (withError) {
        if (Process.arch === "arm64")
            wr.putTstRegImm(convention.errorRegister, ptr(0));
        else
            wr.putCmpRegImm(convention.errorRegister, ptr(0));

        wr.putBCondLabel('ne', 'err_case')
        wr.putRet(); // return if no error

        wr.putLabel('err_case')
        wr.putMovRegReg(convention.firstArgRegister, convention.errorRegister);
        wr[blx](storeError);
    }
    wr.putRet();


    wr.flush();
    wr.dispose();

    Memory.protect(buf, Process.pageSize, 'r-x');
    let callAddr;
    if (Process.arch === "arm64")
        callAddr = buf;
    else
        callAddr = buf.or(ptr(1))
    return {
        'callAddr': callAddr,
        '_buf': buf,
    };
};

function semanticLowering(signature) {
    function typeNeedsIndirection(t) {
        // TODO: generic arguments are also indirect (but we don't have any way to represent generic types yet)
        // TODO: value types containing generic arguments are also indirect
        // TODO: resilient value types are also indirect
        return t.kind === "Existential";
    }
    function addArg(type, indirect, ownership, target, special) {
        if (!indirect && type.kind === "Tuple") {
            type.tupleElements().forEach(e => addArg(e.type, indirect, ownership, target, special));
        } else {
            indirect = indirect || typeNeedsIndirection(type);
            target.push({ type, indirect, ownership, special, });
        }
    }

    let args = [];
    let swiftArgs = signature.getArguments();
    for (let i = 0; i < swiftArgs.length; i++) {
        let indirect = swiftArgs[i].inout;
        let isSelf = i === 0 && false; // TODO
        addArg(swiftArgs[i].type, indirect, args, indirect ? "keep" : "transfer", isSelf ? "self" : null);
    }

    let rets = [];
    addArg(signature.returnType, false, "return_take", rets, null);
    if (signature.flags.doesThrow) {
        addArg(Swift._typesByName.get("Swift.Error"), true, "return_take", rets, "error");
    }

    return { args, rets };
}
function physicalLowering(semantic) {
    let legalTypesAndOffsets = [];
    let specialCases = [];

    let pointerType = "int" + (Process.pointerSize * 8);
    function nextPowerOf2(val) { return Math.pow(2, Math.ceil(Math.log2(val))); }
    function minimalInt(numValues) {
        let log2 = Math.ceil(Math.log2(numValues));
        let nextMultipleOf8 = (8 + log2 - (log2 % 8));
        return nextPowerOf2(nextMultipleOf8);
    }
    function addEmpty(start, end, res) {
        res.push(["empty", start, end]);
    }

    function addSwiftType(type, offset, res) {
        if (res === undefined)
            res = [];

        switch (type.kind) {
            case "Class":
            case "ObjCClassWrapper":
            case "ForeignClass":
            case "Metatype":
            case "Existential":
                res.push([pointer, offset, offset + Process.pointerSize]);
                break;
            case "Struct": {
                let prevEnd = offset;
                type.fields().forEach(f => {
                    let offs = offset + f.offset;

                    if (prevEnd < offs)
                        addEmpty(prevEnd, offs, res);

                    if (f.weak) {
                        res.push([pointer, offs, offs + Process.pointerSize]);
                        prevEnd = offs + Process.pointerSize;
                    } else {
                        addSwiftType(f.type, offs, res);
                        prevEnd = offs + f.type.canonicalType.valueWitnessTable.size;
                    }
                });
                let end = offset + type.canonicalType.valueWitnessTable.size;
                if (prevEnd < end)
                    addEmpty(prevEnd, offs, res);
                break;
            }
            case "Tuple": {
                let prevEnd = offset;
                type.tupleElements().forEach(e => {
                    let offs = offset + e.offset;
                    if (prevEnd < offs)
                        addEmpty(prevEnd, offs, res);

                    addSwiftType(e.type, offs, res)
                    prevEnd = offs + e.type.canonicalType.valueWitnessTable.size;
                });
                let end = offset + type.canonicalType.valueWitnessTable.size;
                if (prevEnd < end)
                    addEmpty(prevEnd, offs, res);
                break;
            }
            case "ErrorObject":
            case "ExistentialMetatype":
            case "Function":
                throw new Error(`conversion to legal type for types of '${type.kind}' not yet implemented`); // TODO
            case "Optional":
            case "Enum": {
                let numPayloads = type.nominalType.enum_.getNumPayloadCases();
                let numEmpty = type.nominalType.enum_.getNumEmptyCases();
                let enumSize = type.canonicalType.valueWitnessTable.size;
                if (numPayloads === 0) {
                    // C-like enum
                    res.push(["int" + (enumSize * 8), offset, offset + enumSize]);
                } else if (numPayloads === 1) {
                    // single-payload enum
                    let payloadType = type.enumCases()[0].type;
                    addSwiftType(payloadType, offset, res); // payload is always at the beginning, possibly followed by discriminant
                    let payloadVwt = payloadType.canonicalType.valueWitnessTable;
                    let extraInhabitants = payloadVwt.extraInhabitantFlags.getNumExtraInhabitants();
                    if (extraInhabitants < numEmpty) {
                        // there is a tag at the end
                        let tagSize = minimalInt(numEmpty + numPayloads);
                        let offs = offset + payloadVwt.size;
                        // TODO: verify that the tag does not get padded for alignment
                        res.push(["int" + tagSize, offs, offs + tagSize]);
                    } else {
                        // no tag
                        res.push(["opaque", offset, offset + enumSize]);
                    }
                } else {
                    // multi-payload enum

                    // We can't use metadata to figure out whether the payload cases have enough overlapping
                    // spare bits.
                    // We can approximate by comparing the size of the largest payload with the size of the enum.
                    let enumCases = type.enumCases();
                    let largestSize = enumCases.reduce((s, c) => {
                        if (c.type)
                            return Math.max(s, c.type.canonicalType.valueWitnessTable.size);
                        else
                            return s;
                    }, 0);

                    // primary tag
                    if (enumSize > largestSize) {
                        res.push(["opaque", offset + largestSize, offset + enumSize]);
                    }

                    // payloads
                    for (let i = 0; i < enumCases.length; i++) {
                        if (enumCases[i].type) {
                            addSwiftType(enumCases[i].type, offset, res);
                        }
                    }

                    // secondary tag for the non-payload cases
                    if (numEmpty > 1) {
                        let tagSize = minimalInt(numEmpty);
                        res.push(["opaque", offset, offset + tagSize]);
                    }
                }
                break;
            }
            case "Opaque": {
                let t = type.getCType();
                if (t === undefined)
                    throw new Error(`the equivalent C type for type '${type}' is not known.`);
                if (t === "pointer")
                    t = pointerType;
                if (t.startsWith("uint"))
                    t = t.slice(1);
                if (t.startsWith("int") && parseInt(t.slice(3)) > convention.maxInt)
                    t = "opaque";
                container.push([t, offset]);
                break;
            }
            default:
                throw new Error(`type '${type}' is of unknown kind '${type.kind}'`);
        }
    }


    for (let i = 0; i < semantic.length; i++) {
        if (semantic[i].special) {
            specialCases.push(semantic[i].special);
            continue;
        }

        if (semantic[i].indirect)
            legalTypesAndOffsets.push([pointerType, 0, Process.pointerSize]);
        else
            legalTypesAndOffsets.push(addSwiftType(semantic[i].type, 0));
    }

    function combineAdjacent() {
        let maps = {
            empty: new Map(),
            opaque: new Map(),
        };
        for (let i = 0; i < legalTypesAndOffsets.length; i++) {
            let legalType = legalTypesAndOffsets[i][0];
            let map = maps[legalType];
            if (map === undefined)
                continue;
            for (let j = legalTypesAndOffsets[i][1]; j < legalTypesAndOffsets[i][2]; j++) {
                if (map.has(j)) {
                    let other = map.get(j);
                    let start = Math.min(legalTypesAndOffsets[i][1], legalTypesAndOffsets[other][1]);
                    let end = Math.max(legalTypesAndOffsets[i][2], legalTypesAndOffsets[other][2]);

                    for (let k = legalTypesAndOffsets[other][1]; k < legalTypesAndOffsets[other][1]; k++) {
                        map.delete(k);
                    }

                    legalTypesAndOffsets[other][1] = start;
                    legalTypesAndOffsets[other][2] = end;
                    i = other - 1; // restart looking for other matches with the new bounds
                    break;
                } else {
                    map.set(j, i);
                }
            }
        }
    }
    combineAdjacent();

    // find overlapped non-empty memory regions
    let indicesByOffset = new Map();
    for (let i =  0; i < legalTypesAndOffsets.length; i++) {
        for (let j = legalTypesAndOffsets[i][1]; j < legalTypesAndOffsets[i][2]; j++) {
            if (!indicesByOffset.has(j))
                indicesByOffset.set(j, []);
            indicesByOffset.get(j).push(i);
        }
    }
    // merge overlapped non-empty memory regions
    for (let [offset, indices] of indicesByOffset.entries()) {
        if (indices.length <= 1)
            continue;

        for (let i = 1; i < indices.length; i++) {
            let t0 = legalTypesAndOffsets[indices[i - 1]];
            let t1 = legalTypesAndOffsets[indices[i]];
            if (t0[0] === t1[0])
                continue;

            t0[0] = t1[0] = "opaque";

        }
    }

    combineAdjacent();

    // end of typed layout

    /* legal type sequence */

    // change types to opaque when their values have wrong alignment
    for (let i =  0; i < legalTypesAndOffsets.length; i++) {
        if (legalTypesAndOffsets[i][0] === "empty" || legalTypesAndOffsets[i][0] === "opaque")
            continue;

        let naturalAlignment;
        let size = legalTypesAndOffsets[i][2] - legalTypesAndOffsets[i][1];
        if (legalTypesAndOffsets[i][0].startsWith("int")) {
            naturalAlignment = Math.min(size, convention.maxVoluntaryInt);
        } else {
            naturalAlignment = size;
        }
        if ((legalTypesAndOffsets[i][1] % naturalAlignment) !== 0) {
            legalTypesAndOffsets[i][0] = "opaque";
        }
    }
    combineAdjacent();

    for (let i =  0; i < legalTypesAndOffsets.length; i++) {
        let size = legalTypesAndOffsets[i][2] - legalTypesAndOffsets[i][1];
        if (legalTypesAndOffsets[i][0].startsWith("int") && size <= convention.maxVoluntaryInt)
            legalTypesAndOffsets[i][0] = "opaque";
    }
    combineAdjacent();

    combineAdjacent = undefined; // make sure we don't combine anything below this point.
    // split opaque values at maximal aligned storage units
    for (let i = 0; i < legalTypesAndOffsets.length; i++) {
        if (legalTypesAndOffsets[i][0] !== "opaque")
            continue;
        let start = legalTypesAndOffsets[i][1];
        let end = legalTypesAndOffsets[i][2];
        let nextBoundary = start - (start % convention.maxVoluntaryInt) + convention.maxVoluntaryInt;
        while (nextBoundary < end - (end % convention.maxVoluntaryInt)) {
            legalTypesAndOffsets.push(["opaque", start, nextBoundary]);
            start = nextBoundary;
            nextBoundary += convention.maxVoluntaryInt;
        }
        legalTypesAndOffsets[i][1] = start;
    }
    // turn opaques into integers
    let perStorageUnit = new Map();
    let lastStorageUnit = 0;
    for (let i = 0; i < legalTypesAndOffsets.length; i++) {
        if (legalTypesAndOffsets[i][0] !== "opaque")
            continue;
        let start = legalTypesAndOffsets[i][1];
        let storageUnit = (start - (start % convention.maxVoluntaryInt)) / convention.maxVoluntaryInt;
        if (!perStorageUnit.has(storageUnit))
            perStorageUnit.set(storageUnit, []);
        perStorageUnit.get(storageUnit).push(i);
        lastStorageUnit = Math.max(lastStorageUnit, storageUnit);
    }
    let toRemove = [];
    for (let sharedUnit of perStorageUnit.values()) {
        let start = Number.POSITIVE_INFINITY;
        let end = Number.NEGATIVE_INFINITY;
        for (let i of sharedUnit) {
            start = Math.min(legalTypesAndOffsets[i][1], start);
            end = Math.max(legalTypesAndOffsets[i][2], end);
        }
        // remove all but one of the opaque values in this storage unit
        toRemove = toRemove.concat(sharedUnit.slice(1));

        let size;
        for (size = 1; start + size < end; size *= 2) { }
        let newStart = start & ~(size - 1);
        if (newStart != start)
            size *= 2;

        let newEnd = newStart + size;
        legalTypesAndOffsets[sharedUnit[0]] = ["int" + (size * 8).toString(), newStart, newEnd];
    }
    toRemove.sort().reverse();
    for (let i of toRemove) {
        legalTypesAndOffsets.splice(i, 1);
    }

    legalTypesAndOffsets.sort((a, b) => a[1] - b[1]);

    return legalTypesAndOffsets;
}


function convertToCParams(signature) {
    let [semanticArgs, semanticRets] = semanticLowering(signature);
    let [physicalArgs, physicalRets] = [semanticArgs, semanticRets].map(physicalLowering);



    // TODO: for generic functions, generic arguments are always passed indirectly, and arguments with the
    // type metadata of those arguments are added at the end of the arg list
    let lowered = [];
    let argInfos = [];

    // expand tuples into their components
    let argTypes = [];
    for (let i = 0; i < method.args.length; i++) {
        let elem = toCheck.shift();
        if (elem.kind === "Tuple") {
            toCheck = elem.elements.map(e => e.type).concat(toCheck);
        } else {
            argTypes.push(elem);
        }
    }

    // see NativeConventionSchema::getCoercionTypes
    for (let i = 0; i < params.length; i++) {
        // TODO: floats/doubles, vectors
        // see classifyArgumentType in swift-clang/lib/CodeGen/TargetInfo.cpp
        let type = method.args[i].type;
        let lowering = getLowering(params[i]);
        let vwt = type.canonicalType.valueWitnessTable;
        if (vwt.size === 0) // ignore zero-sized types
            continue;

        if (method.args[i].inout || vwt.flags.IsNonBitwiseTakable || vwt.size > CC.maxInlineArgument) {
            lowered.push({size: Process.pointerSize, stride: Process.pointerSize, indirect: true});
        } else {
            lowered.push({size: vwt.size, stride: vwt.stride, indirect: false});
        }
    }

    // see SwiftAggLowering::finish
    let remainingSpace = 0;
    for (let i = 0; i < lowered.length; i++) {

    }

    let indirectReturn = false;
    let cReturnType = 'void';
    if (method.returnType) {
        let vwt = method.returnType.valueWitnessTable;
        // TODO: verify these are the right conditions for indirect returns
        if (vwt.size > CC.maxInlineReturn || vwt.flags.IsNonPOD) {
            indirectReturn = true;
            lowered.unshift({size: Process.pointerSize, stride: Process.pointerSize, indirect: true});
        } else {
            let alignedSize = vwt.size;
            let remaining = 0;
            cReturnType = [];
            for (let size of [8, 4, 2, 1]) {
                // TODO: specify larger integers for int types larger than pointers
                while (size <= convention.maxVoluntaryInt && alignedSize > 0 && alignedSize % size === 0) {
                    // TODO: floats/doubles, vectors
                    cReturnType.push('uint' + (size * 8).toString());
                    alignedSize -= size;
                }
            }
        }
    }

    let overlappedWithSuccessor = new Set();
    for (let i = 0; i < params.length; i++) {

    }

    let cParams = [], cArgTypes = [];
    for (let i = 0; i < params.length; i++) {
    }

    return {cParams, lowered};
}

module.exports = {
    convention,
    makeCallTrampoline,
    checkTrampolineError,
};
