#!/usr/bin/env python3

import json
import os.path
import sys
from subprocess import run
from tempfile import NamedTemporaryFile

import frida

from pycparser.c_ast import Decl, Enum, Enumerator, IdentifierType, PtrDecl, Struct, TypeDecl, Typedef
from pycparser.c_generator import CGenerator
from pycparser.c_parser import CParser

dev = next(iter(dev for dev in frida.enumerate_devices() if dev.type == 'usb'))
session = dev.attach(sys.argv[1])
with NamedTemporaryFile() as tmp:
    run(['frida-compile', '-o', tmp.name, os.path.join(os.path.dirname(__file__), './c_header_gen.js')], check=True)
    with open(tmp.name) as script_file:
        script_source = script_file.read()
script = session.create_script(script_source)


def recv(message, data):
    if message['type'] == 'error':
        session.detach()
        print(message['description'], file=sys.stderr)
        print(message['stack'], file=sys.stderr)
        sys.exit(1)

def top_sort(dag):
    empty = set()
    no_incoming = set(dag.keys())
    # we need to be able to query incoming edges
    rev_dag = {}
    for source_node, target_nodes in dag.items():
        for target_node in target_nodes:
            no_incoming.discard(target_node)
            rev_dag.setdefault(target_node, set()).add(source_node)
    while no_incoming:
        # pick a node without incoming edges
        node = no_incoming.pop()
        yield node
        # remove the node from the graph, add dependents to no_incoming
        for target_node in list(dag.get(node, [])):
            dag[node].remove(target_node)
            if not dag[node]:
                del dag[node]
            rev_dag[target_node].remove(node)
            if not rev_dag[target_node]:
                del rev_dag[target_node]
                no_incoming.add(target_node)

    assert not rev_dag, "graph is not a DAG"



def remove_generic(name):
    if not name.endswith(">"):
        return name

    closed = 1
    generic_params = []
    for i in range(len(name) -2, -1, -1):
        if name[i] == '>' and name[i-1] != '-':
            closed += 1
        elif name[i] == '<':
            closed -= 1

        if closed == 0:
            return name[:i]
    raise Exception("invalid type declaration: " + repr(name))


def print_header(message):
    generator = CGenerator()
    parser = CParser()

    def del_spaces(name):
        if name.startswith('(extension in '):
            idx = name.index('):')
            name = '_extension_in_' + name[14:idx] + "__" + name[idx+2:]

        # file private types
        if ' in _' in name:
            idx = name.index(' in _')
            end = name.index(')', idx)
            start = name.rindex('(', None, idx)
            namespace = name[:start]
            if '>' in namespace:
                namespace = mangle_name(namespace[:-1]) + '.'
            name = namespace + name[start+1:idx] + name[end+1:]
        return name

    def mangle_name(human):
        if human in ('void*', 'voidp', 'Metadata*'):
            return human
        if human == '()':
            return 'void'

        info = types[human]
        if 'getGenericParams' in info and info['getGenericParams']:
            name = remove_generic(human)
        else:
            name = human

        if name.startswith('?Unknown type of'):
            name = name.replace('?Unknown type of ', 'XXX_unknown_type_of_')

        if name.startswith("Static #"):
            spl = name.split(' ', 4)
            return "_static_no" + spl[1][1:] + "_in_" + spl[3] + "__func" + str(hash(spl[4]))[1:]
        name = del_spaces(name)

        outp = f'swift_{info["kind"]}__'

        if info['kind'] == "Tuple":
            elems = []
            for e in info['tupleElements']:
                name = mangle_name(e['type'])
                if e['label']:
                    name += "__as_" + e['label']
                elems.append(name)
            outp += "with__" + "__and__".join(elems)
        elif info['kind'] == "Existential":
            protos = []
            for p in info['protocols']:
                protos.append(del_spaces(script.exports.demangle(p)).replace(".", "__"))
            if info['isClassBounded']:
                protos.append("Swift__AnyObject")
            if protos:
                outp += "conforming_to__" + "__and__".join(protos)
            else:
                outp += "Any"
            if info.get('getSuperclassConstraint'):
                outp += "__inheriting_from_" + mangle_name(info['getSuperclassConstraint'])
        elif info['kind'] == 'Function':
            return "func_" + str(hash(name))[1:]
        else:
            outp += name.replace(".", "_")

        if 'getGenericParams' in info and info['getGenericParams']:
            gen_params = [mangle_name(param) for param in info['getGenericParams']]
            outp += "__of__" + "__and__".join(gen_params)

        return outp


    def make_decl(name, offset, type_name):
        nonlocal decls, pad_count, parser, prev_end

        if isinstance(offset, str):
            assert offset[:2] == '0x'
            offset = int(offset, 16)

        if prev_end < offset:
            pad_str = f"char _padding{pad_count}[{offset - prev_end}];"
            decls.append(parser.parse(pad_str).ext[0])
            pad_count += 1

        type_decl = TypeDecl(name.replace(".", "__"), None, IdentifierType([mangle_name(type_name)]))
        decls.append(Decl(None, None, None, None, type_decl, None, None))

        req_graph.setdefault(type_name, set()).add(parent_name)

        if offset != -1:
            size = pointer_size if type_name.endswith('*') else int(types[type_name]['size'], 16)
            prev_end = offset + size

    #print("#include <stdint.h>")
    print("#pragma pack(1)")
    print("typedef void *voidp;")
    print("typedef struct Metadata_s Metadata;")
    types = json.loads(message)

    req_graph = {}
    ptr_types = {'void*', 'voidp', 'Metadata*'}
    ctypes = {}

    for name, info in types.items():
        pad_count = 0
        decls = []
        prev_end = 0
        ctype = None
        parent_name = name
        if info['kind'] == "Tuple":
            for i, elem in enumerate(info['tupleElements']):
                make_decl(elem['label'] or f'_{i}', elem['offset'], elem['type'])
            ctype = Struct(mangle_name(name) + "_s", decls)
        elif info['kind'] == "ObjCClassWrapper":
            print(f'typedef struct {mangle_name(name)}_s *{mangle_name(name)};')
        elif info['kind'] in ("Struct", "Class"):
            if info['kind'] == 'Class':
                make_decl('_isa', '0x0', 'Metadata*')
                #make_decl('_refCounts', hex(pointer_size), 'size_t')

            for i, field in enumerate(info['fields']):
                make_decl(field['name'], field['offset'], field['type'])
            ctype = Struct(mangle_name(name) + "_s", decls)

            if info['kind'] == 'Class':
                ctype = PtrDecl(None, ctype)
        elif info['kind'] == "Existential":
            if info['isClassBounded'] or info.get('getSuperclassConstraint'):  # class existential container
                make_decl(f'heap_object', -1, 'void*')
            else:  # opaque existential container
                union = "union { void *heapObject; void *fixedSizeBuffer[3]; };"
                decls.append(parser.parse(union).ext[0])
                make_decl("dynamicType", -1, "Metadata*")
            for i in range(info['witnessTableCount']):
                make_decl(f'_witnessTable{i + 1}', -1, 'void*')
            ctype = Struct(mangle_name(name) + "_s", decls)
        elif info['kind'] in ("Enum", "Optional"):
            if info['enumCases'] and info['enumCases'][0]['name'] is None:
                # C-like enum
                # we don't have case names or values, so just generate a typedef to an int type
                print(f"typedef uint{int(info['size'], 16) * 8}_t {mangle_name(name)};")
            elif len(info['enumCases']) == 0:
                ctype = Struct(mangle_name(name) + "_s", decls)
            elif len(info['enumCases']) == 1 and info['enumCases'][0]['type']:
                make_decl(info['enumCases'][0]['name'], 0, info['enumCases'][0]['type'])
                ctype = Struct(mangle_name(name) + "_s", decls)
            else:
                print(f'typedef struct {mangle_name(name)}_s {{ char _data[{info["size"]}]; }} {mangle_name(name)};')
        elif info['kind'] == 'Opaque':
            if 'getCType' in info:
                ctype_names = {
                    'pointer': 'void*',
                    'int8': 'int8_t',
                    'int16': 'int16_t',
                    'int32': 'int32_t',
                    'int64': 'int64_t',
                    'int64': 'int64_t',
                }
                print(f'typedef {ctype_names[info["getCType"]]} {mangle_name(name)};')
            elif name == 'Builtin.NativeObject':
                print(f'typedef void *{mangle_name(name)};')
            else:
                print(f'typedef char {mangle_name(name)}[{info["size"]}];')
        elif info['kind'] == 'Function':
            print(f"typedef void *func_{str(hash(name))[1:]};")  # TODO: proper names
        else:
            print(f'typedef char {mangle_name(name)}[{info["size"]}];')

        if ctype:
            type_decl = TypeDecl(mangle_name(name), None, ctype)
            ctypes[name] = type_decl
            type_decl_forward = Struct(mangle_name(name) + "_s", [])
            if isinstance(type_decl, PtrDecl):
                ptr_types.add(name)
                type_decl_forward = PtrDecl(None, type_decl_forward)
                print(generator.visit(Typedef(mangle_name(name), None, ['typedef'], type_decl_forward)) + ";")

    for name in ptr_types:
        req_graph.pop(name, None)

    for name in top_sort(req_graph):
        if name in ctypes:
            print(f"\n// {name}")
            print(generator.visit(Typedef(mangle_name(name), None, ['typedef'], ctypes[name])) + ";")

script.on('message', recv)
script.load()
pointer_size = script.exports.pointerSize()
print_header(script.exports.run(*sys.argv[2:]))
session.detach()
sys.exit(0)
