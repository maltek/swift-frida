'use strict';

require('../../loader');

function makeJsonCompat(obj) {
    switch (typeof obj) {
        case "number":
        case "string":
        case "boolean":
        case "undefined":
            return obj;
    }
    if (obj === null)
        return null;
    if (obj instanceof NativePointer || obj instanceof Int64 || obj instanceof UInt64)
        return obj.toString();

    // use type names in place of type objects
    let res = obj instanceof Array ? [] : {};
    for (let prop of Object.keys(obj)) {
        if (["canonicalType", "nominalType", "getSize", "fixedName", "_name", "Type", "withoutClassBound", "getObjCObject", "withClassBound"].indexOf(prop) !== -1)
            continue;

        let val = obj[prop];

        // call through functions
        if (val instanceof Function && !("isGeneric" in val)) {
            if (val.length == 0)
                val = val.call(obj);
            else
                continue;
        }

        // replace type objects with their names
        if (val && typeof val === "function" && "isGeneric" in val) {
            val = val.toString();
        }

        res[prop] = makeJsonCompat(val);
    }
    return res;
}

rpc.exports = {
    run() {
        const types = Swift.enumerateTypesSync();
        let out = {};
        types.forEach(t => {
            if (t.isGeneric())
                return;

            out[t.toString()] = makeJsonCompat(t);
            if (t.kind === "Existential")
                out[t.toString()].witnessTableCount = t.canonicalType.flags.getNumWitnessTables();
            if (t.kind != "Class" || t.canonicalType.isTypeMetadata())
                out[t.toString()].size = t.canonicalType.valueWitnessTable.size;
            else
                out[t.toString()].size = '0x' + Process.pointerSize.toString(16);
        });
        return JSON.stringify(out);
    },
    demangle(str) {
        return Swift.isSwiftName(str) ?  Swift.demangle(str) : str;
    },
    pointersize() {
        return Process.pointerSize;
    },
};
