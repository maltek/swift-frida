'use strict';

const Swift = require('../../index');
let types = new Map();

global.Swift = Swift;


r2frida.pluginRegister('swift', function(name) {
    if (name === 'swa') {
        return function(args) {
            for (let [key, val] of Swift.enumerateTypesSync(...args)) {
                types.set(key, val);
            }
            global.swiftTypes = types;
            return `found ${types.size} types`;
        };
    }
    if (name === 'swt') {
        return function(args) {
            if (types === null) {
                throw new Error("please run the '\\swa' command first!");
            }
            let msgs = [];
            let name = args.join(" ");
            let t = types.get(name);
            if (t === undefined) {
                msgs.push(`Type '${name}' not found!`);
                if (name.indexOf('<') !== -1) {
                    msgs.push(`Hint: maybe you need to manually instantiate it from its generic base.`);
                }
                throw new Error(msgs.join("\n"));
            }
            msgs.push(`${t}: ${t.nominalType} ${t.canonicalType}`);
            if ('getSize' in t && t.getSize() !== undefined)
                msgs.push(`size: ${t.getSize()} bytes`);
            msgs.push(`kind: ${t.kind}`);

            if (t.isGeneric()) {
                let numParams;
                if (t.nominalType && !t.nominalType.genericParams.flags.HasGenericParent) {
                    numParams = t.nominalType.genericParams.flags.numGenericRequirements;
                } else {
                    numParams = "unknown number of";
                }
                msgs.push(`Generic with ${numParams} generic requirements.`);
            }
            if ('enumCases' in t) {
                msgs.push(`cases:`);
                for (let enumCase of t.enumCases()) {
                    let caseStr = "\t";
                    if (enumCase.indirect)
                        caseStr += "indirect ";
                    if (enumCase.weak)
                        caseStr += "weak ";

                    caseStr += enumCase.name;

                    if (enumCase.type) {
                        if (enumCase.type.kind === "Tuple")
                            caseStr += enumCase.type;
                        else
                            caseStr += `(${enumCase.type})`;
                    }
                    msgs.push(caseStr);
                }
            }
            if ('fields' in t) {
                msgs.push('fields:');
                for (let field of t.fields()) {
                    let fieldStr = "";
                    if (field.weak)
                        fieldStr += "weak ";
                    msgs.push(`\t${fieldStr}${field.name}: ${field.type}, offset ${field.offset}`);
                }
            }
            if ('tupleElements' in t) {
                for (let elem of t.tupleElements()) {
                    let tupleStr = "";
                    if (elem.label)
                        tupleStr += `${elem.label}: `;
                    msgs.push(`\t${tupleStr}${elem.type}, offset: ${elem.offset}`);
                }
            }
            return msgs.join("\n\t");
        };
    }
    if (name === 'swtl') {
        return function() {
            if (types === null) {
                throw new Error("please run the '\\swa' command first!");
            }

            let msgs = [];
            for (let name of types.keys()) {
                msgs.push(name);
            }
            return msgs.join("\n");
        };
    }

    if (name === 'swdg') {
        return function(args) {
            if (types === null) {
                throw new Error("please run the '\\swa' command first!");
            }

            for (let name of args) {
                if (!types.has(name)) {
                    throw new Error(`No type named '${name}' is known!`);
                }
            }

            let baseType = types.get(args.shift());
            let typeParams = args.map(name => types.get(name));

            if (!baseType.isGeneric()) {
                throw new Error(`'${baseType}' is not a generic type!`);
            }

            let type = baseType.withGenericParams(...typeParams);
            types.set(type.toString(), type);
            return `successfully instantiated type '${type}'`;
        };
    }
    if (name === 'swp') {
        return function(args) {
            if (types === null) {
                throw new Error("please run the '\\swa' command first!");
            }
            let [name, ...addrs] = args;

            let type = types.get(name);
            if (type === undefined) {
                throw new Error(`Type '${name}' not found!`);
            }
            return addrs.map(ptr).map(addr => new type(addr).toString()).join("\n");
        };
    }
    if (name === 'swiD') { // demangle symbol name
        return function(args) {
            return args.map(Swift.demangle).join("\n");
        };
    }
    if (name === 'swis') { // list demangled symbols
    }
    if (name === 'sw?') {
        return function() {
            return "r2swida help\n" +
                "\n" +
                "\\sw?                                  \tShow this help.\n" +
                "\\swiD <name>...                       \tDemangle one or more Swift names.\n" +
                "\\swa [<lib>...]                       \tCollect information about Swift types (from <lib>, or everywhere). Needs to be run before most other commands work.\n" +
                "\\swp <type> <addr>...                 \tDump the Swift variable(s) of type <type> at <addr>.\n" +
                "\\swdg <generic_type> <type_params>... \tInstantiate the generic type <generic_type> with the type parameters <type_params>.\n" +
                "\\swt <type>                           \tShow information about the type named <type>. Note: quote the whole command with \" to avoid problems with special characters in the type name.\n" +
                "\\swtl                                 \tList all types that were found by '\\swa'.\n"
        };
        // TODO: help
    }
    // TODO: allow creating other kinds of types (tuples, meta, ...)
});
