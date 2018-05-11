# C header generation

This example uses the type information collected from within Frida to generate a
C header file that you can load into a static analysis tool like radare2 or IDA Pro.

You need to install `pycparser` for Python 3, then you can run it like this:

    ./c_header_gen.py AppName > /tmp/app_name_defs.h

The output will have many C struct definitions like this one:

    // Swift.UnsafeRawBufferPointer.Iterator
    typedef struct swift_Struct__Swift_UnsafeRawBufferPointer_Iterator_s
    {
      swift_Optional__Swift_Optional__of__swift_Struct__Swift_UnsafeRawPointer _position;
      swift_Optional__Swift_Optional__of__swift_Struct__Swift_UnsafeRawPointer _end;
    } swift_Struct__Swift_UnsafeRawBufferPointer_Iterator;
