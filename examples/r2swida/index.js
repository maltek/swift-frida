'use strict';

const Swift = require('../../index');
let types = null;

r2frida.pluginRegister('swift', function(name) {
    if (name === 'swa') {
        return function(args) {
            types = Swift.enumerateTypesSync();
            console.log(`found ${types.size} types`);
        };
    }
    if (name === 'swt') {
        return function(args) {
            if (types === null) {
                throw new Error("please run the '\\swa' command first!");
            }
            for (let name of args) {
                let t = types.get(name);
                if (t === undefined) {
                    console.log(`Type '${name}' not found!`);
                    if (name.indexOf('<') !== -1) {
                        console.log(`Hint: maybe you need to manually instantiate it from its generic base.`);
                    }
                } else {
                    console.log(`${name}:\nsize: ${t.getSize().toInt32()} bytes\nkind: ${t.kind}`);
                    if (t.isGeneric()) {
                        let numParams;
                        if (t.nominalType && !t.nominalType.genericParams.flags.HasGenericParent) {
                            numParams = t.nominalType.genericParams.flags.numGenericRequirements;
                        } else {
                            numParams = "unknown number of";
                        }
                        console.log(`Generic with ${numParams} generic requirements.`);
                    }
                    if ('enumCases' in t) {
                        console.log(`cases:`);
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
                            console.log(caseStr);
                        }
                    }
                    if ('fields' in t) {
                        console.log('fields:');
                        for (let field of t.fields()) {
                            let fieldStr = "";
                            if (field.weak)
                                fieldStr += "weak ";
                            console.log(`\t${fieldStr}${field.name}: ${field.type}, offset ${field.offset}`);
                        }
                    }
                    if ('tupleElements' in t) {
                        for (let elem of t.tupleElements()) {
                            let tupleStr = "";
                            if (elem.label)
                                tupleStr += `${elem.label}: `;
                            console.log(`\t${tupleStr}${elem.type}, offset: ${elem.offset}`);
                        }
                    }
                }
            }
        };
    }
    if (name === 'swtl') {
        return function() {
            if (types === null) {
                throw new Error("please run the '\\swa' command first!");
            }

            for (let name of types.keys()) {
                console.log(name);
            }
        };
    }

    if (name === 'swdg') {
        return function(args) {
            if (types === null) {
                throw new Error("please run the '\\swa' command first!");
            }

            for (let name of args) {
                if (!types.has(name)) {
                    console.log(`No type named '${name}' is known!`);
                    return;
                }
            }

            let baseType = types.get(args.shift());
            let typeParams = args.map(name => types.get(name));

            if (!baseType.isGeneric()) {
                console.log(`'${baseType}' is not a generic type!`);
            }

            let type = baseType.withGenericParams(...typeParams);
            types.set(type.toString(), type);
            console.log(`successfully instantiated type '${type}'`);
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
                console.log(`Type '${name}' not found!`);
                return;
            }
            addrs = addrs.map(ptr);

            for (let addr of addrs) {
                console.log(new type(addr).toString());
            }
        };
    }
    if (name === 'swid') { // demangle symbol name
        return function(args) {
            for (let name of args) {
                console.log(Swift.demangle(name));
            }
        };
    }
    if (name === 'swis') { // list demangled symbols
    }
    if (name === 'sw?') {
        return function() {
            console.log("r2swida help");
            console.log("");
            console.log("\\sw?                                  \tShow this help.");
            console.log("\\swid <name>...                       \tDemangle one or more Swift names.");
            console.log("\\swa                                  \tCollect information about Swift types. Needs to be run before most other commands work.");
            console.log("\\swp <type> <addr>...                 \tDump the Swift variable(s) of type <type> at <addr>.");
            console.log("\\swdg <generic_type> <type_params>... \tInstantiate the generic type <generic_type> with the type parameters <type_params>.");
            console.log("\\swt <type>...                        \tShow information about the type(s) <type>.");
            console.log("\\swtl                                 \tList all types that were found by '\\swa'.");
        };
        // TODO: help
    }
    // TODO: allow creating other kinds of types (tuples, meta, ...)
});
