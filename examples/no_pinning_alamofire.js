'use strict';

// disable certificate pinning/evaluation for the Alamofire library (on AARCH64)
//
// It hooks the function that decides which validation policy to use and always
// returns that no validation should be done.

const Swift = require('../index');

setTimeout(function() {
    console.log("starting");
    // collect types into typesByName
    let typesByName = Swift.enumerateTypesSync("Alamofire");
    Swift.enumerateTypesSync("libswiftCore.dylib");

    let ServerTrustPolicy = typesByName.get("Alamofire.ServerTrustPolicy");
    // instantiate Optional<T> with ServerTrustPolicy as type parameter
    let OpServerTrustPolicy = typesByName.get("Swift.Optional<_T0>").withGenericParams(ServerTrustPolicy);

    // [iPhone::yomo]-> Swift.demangle("_T09Alamofire24ServerTrustPolicyManagerC06servercD0AA0bcD0OSgSS7forHost_tF")
    // "Alamofire.ServerTrustPolicyManager.serverTrustPolicy(forHost: Swift.String) -> Swift.Optional<Alamofire.ServerTrustPolicy>"
    let serverTrustPolicy = Module.findExportByName("Alamofire", "_T09Alamofire24ServerTrustPolicyManagerC06servercD0AA0bcD0OSgSS7forHost_tF");
    //
    Interceptor.attach(serverTrustPolicy, {
        onLeave: function(result) {
            console.log("x");
            // we need to copy the registers into memory before we can access them
            let buf = Memory.alloc(Process.pointerSize * 3); // OpServerTrustPolicy.getSize() = 0x12 -> 3 pointers
            Memory.writePointer(buf, this.context.x0);
            Memory.writePointer(buf.add(Process.pointerSize), this.context.x1);
            Memory.writePointer(buf.add(Process.pointerSize * 2), this.context.x2);

            // create a JavaScript wrapper for the Swift object in memory
            let val = new OpServerTrustPolicy(buf);

            // print the old policy
            console.log(val);

            if (OpServerTrustPolicy.enumCases()[val.$enumCase].name === "some") {
                // create a copy of the payload
                let inside = val.$allocCopy().$enumPayloadCopy();
                // change the copy to disable validation and pinning
                inside.$setTo(ServerTrustPolicy.enumCases().filter(c => c.name === "disableEvaluation")[0]);

                // copy the modified policy back into the optional
                val.$setTo(OpServerTrustPolicy.enumCases().filter(c => c.name === "some")[0], inside);

                // destroy the copied policy -- happens automatically on GC, but let's not wait that long!
                inside.$destroy();

                // print the new policy
                console.log(val);

                // copy back the enumeration from memory to registers
                this.context.x0 = Memory.readPointer(buf);
                this.context.x1 = Memory.readPointer(buf.add(Process.pointerSize));
                this.context.x2 = Memory.readPointer(buf.add(Process.pointerSize * 2));
            }
        }
    });
    console.log("OK");
}, 0);
