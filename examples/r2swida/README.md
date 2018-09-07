# r2swida

Swift plugin for [r2frida](https://github.com/nowsecure/r2frida). Compile with
`frida-compile -w -o /tmp/r2swida.js examples/r2frida/`. Usage:

    [0x00000000]> \. /tmp/r2swida.js
    {}
    [0x00000000]> \sw?
    r2swida help

    \sw?                                    Show this help.
    \swiD <name>...                         Demangle one or more Swift names.
    \swa [<lib>...]                            Collect information about Swift types (from <lib>, or everywhere). Needs to be run before most other commands work.
    \swp <type> <addr>...                   Dump the Swift variable(s) of type <type> at <addr>.
    \swdg <generic_type> <type_params>...   Instantiate the generic type <generic_type> with the type parameters <type_params>.
    \swt <type>                             Show information about the type named <type>. Note: quote the whole command with \" to avoid problems with special characters in the type name.
    \swtl                                   List all types that were found by '\swa'.

After executing `\swa`, you can access the result of `Swift.enumerateTypesSync`
as the `swiftTypes` variable when running JavaScript code with `\eval`.
