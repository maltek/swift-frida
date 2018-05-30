'use strict';

// disable certificate pinning/evaluation for the Alamofire library

const Swift = require('../index');

Swift.enumerateTypesSync().length; // collect all types into _typesByName
let ServerTrustPolicy = Swift._typesByName.get("Alamofire.ServerTrustPolicy");
let OpServerTrustPolicy = Swift._typesByName.get("Swift.Optional<_T0>").withGenericParams(ServerTrustPolicy);
let serverTrustPolicy = Module.findExportByName(null, "_T09Alamofire24ServerTrustPolicyManagerC06servercD0AA0bcD0OSgSS7forHost_tF");
Interceptor.attach(serverTrustPolicy, {
    onLeave: function(result) {
        let buf = Memory.alloc(Process.pointerSize * 3);
        Memory.writePointer(buf, this.context.x0);
        Memory.writePointer(buf.add(Process.pointerSize), this.context.x1);
        Memory.writePointer(buf.add(Process.pointerSize * 2), this.context.x2);

        let val = new OpServerTrustPolicy(buf);
        console.log(val);
        let inside = val.$allocCopy().$enumPayloadCopy();
        inside.$setTo(ServerTrustPolicy.enumCases().filter(c => c.name === "disableEvaluation")[0]);
        val.$setTo(OpServerTrustPolicy.enumCases().filter(c => c.name === "some")[0], inside);
        inside.$destroy();
        console.log(val);

        this.context.x0 = Memory.readPointer(buf);
        this.context.x1 = Memory.readPointer(buf.add(Process.pointerSize));
        this.context.x2 = Memory.readPointer(buf.add(Process.pointerSize * 2));
    }
});
