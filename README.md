# swift-frida

Swift runtime interop from Frida. (See [frida-swift](https://github.com/frida/frida-swift) instead, if you're looking to talk to Frida from Swift code you write.)

## Status

This is a work-in-progress, so expect some bugs and missing functionality! 

I'm mainly testing things on iOS 11.1.2 (64bit), every now and then also on iOS 9.3.5 (32bit). I haven't looked at any other platform at all. I'm only testing with Apps using Swift 4.0 at the moment.


## Available APIs

Right now, the following functions are available in the `Swift` namespace, when the script is loaded:

 * `available` Allows you to check if the current process uses Swift. Don't use any of the other functions here if this property is `false`.
 * `isSwiftName(name)` Takes a function/symbol name (like you can get from `Module` objects), and returns a boolean indicating whether it is a mangled Swift name or not.
 * `demangle(name)` Takes a mangled Swift name (like you can get from `Module` objects), and returns a demangled, human-readable String for it.
 * `getMangled(name)` The opposite of `demangle(name)`. Right now, this only works for names that were previously returned by `demangle(name)`.
 * `_api` This is an object providing access to many low-level functions in the Swift runtime.
 * `_typeFromCanonical(metadata)` This function allows you to create a `Type` constructor from a low-level `Metadata*`.
 * `_typesByName` A `Map` storing all the types found by the last invocation of `enumerateTypesSync()`, with their names as keys.
 * `makeFunctionType(args, returnType, flags)` Creates a new Swift `Type` constructor for a function type. `args` should be an array with the types of each argument, `flags` is an optional object with `doesThrow` and/or `convention` properties.
 * `makeTupleType(labels, innerTypes)` Creates a new Swift `Type` constructor for a tuple type. `labels` and `innerTypes` are arrays with the labels and types of the tuple elements. Use empty strings for unlabeled elements.
 * `enumerateTypesSync()` Returns an array with the information about all Swift data types defined in the Swift program. The returned objects have a `toString` method returning the fully qualified name of the type, including generic bounds (if possible) and a string property `kind` that tells you which kind of type (e.g. `"Class"`, `"Struct"`) it is. The `Type` property returns a `Type` constructor for the meta type of the represented type. Depending on the kind of type, additional methods are available:
 
    Kind             | available method
    -----------------|---------------------------------------------------------------------------------------------------------------
    Enum             | `enumCases` returns an array with all defined cases, with their names, types, and attributes.
    Class, Struct   | `fields` returns an array with all fields of this class or struct, with names, offsets, types, and attributes.
    Tuple            | `tupleElements` returns an array with the types and labels of the elements in the tuple.
    Function         | `returnType` returns the return type of the function.
    Function         | `functionFlags` returns an object telling you the calling convention and whether the function throws or not.
    Function         | `getArguments` returns an array with the type and flags (`inout`) for every function argument.
    ObjCClassWrapper | `getObjCObject` returns an `ObjC.Object` describing this class.

    Uninstantiated generic types (you can check this with the `isGeneric` method), do not have any of these methods available. You must call `withGenericParams` to get a fully concrete type.

    For fully instantiated generic types or non-generic types, you can use these type objects as constructors -- you provide a pointer where a value of that type is stored, and get back an object that lets you interact with this variable. Note that this object only stays valid for as long as this pointer is valid and is not modified (except using methods directly on this object). Depending on the kind of type, the following properties exist:

    Kind               | available property
    -------------------|---------------------------------------------------------------------------------------------------------------
    \*                  | `toString()` returns a string with the debug representation of this variable
    \*                 | `$pointer` the pointer where this value resides in memory
    \*                 | `$type` the dynamic type of this value
    \*                 | `$staticType` the static type of this value
    \*                 | `$destroy()` destroys an owned Swift value. (On a best-effort basis this also happens when the object is garbage-collected.)
    \*                 | `$assignWithCopy(other)` assigns a copy of `other` to this variable. `other` must have a compatible type (this is not checked).
    \*                 | `allocCopy()` creates and returns an owned copy of this value. Use `$destroy()` on the return value when you are done using it!
    Function           | The object is a function that you can call. (Other properties are still available.)
    ObjCClassWrapper   | The object is an `ObjC.Object`. See the documentation there. (None of the properties for Swift values are available.)
    Class, Existential | `$isa` the isa pointer. (Only for Existential types when they are class bound.)
    Class, Existential | `$retainCounts` the number of references to this value. (Only for Existential types when they are class bound.)
    Enum               | `$enumCase' the index of the active case of this enum, see `$type.enumCases`.
    Enum               | `$enumPayloadCopy()` creates and returns an owned copy of the payload of this enum, or returns `undefined` if the active case has no payload. Use `$destroy()` on the return value when you are done using it!
    Class, Struct      | Getters and setters for every field (see `$type.fields()`). When the field name collides with a property that exists on every JS object, or starts with a `$`, use `$$` as a name to access such a field.
    Existential        | `$value` allows you to get/set the value in this variable. (Only for Existential types when they are not class bound.)
    Tuple              | Getters and setters for every tuple element (see `$type.tupleElements()`, by index or (when available) by label.

    Returned values are normally the same kind of `SwiftValue` objects, except that for integers and booleans which are transparently converted into their JavaScript equivalents. For strings, you can use `toString()` and `$assignWithCopy` to convert between the JavaScript and Swift types.




But, again, this is completely unstable and might change at any time.

## Test Setup

For testing, you want to run a command like this, to recompile whenever you change the scripts:

    frida-compile -w -o /tmp/swift.js loader

Then, you can just run Frida interactively, with the Swift module loaded:

    frida -U -n Foo -l /tmp/swift.js

You can now play with the functions of the `Swift` object.  (After making a change to a file in this repo, use `%reload` to reload the Swift script after recompiling.)


## License
Code in `metadata.js` is based on Apache-2.0 licensed Swift compiler source code.
Code in `index.js` is based on wxWindows-3.1 licensed frida-objc source code.

The compatible intersection of those licenses is LGPL-3.0 (or later) with
wxWindows exceptions. So that's also the license terms under which we release
the original code in this repository.
