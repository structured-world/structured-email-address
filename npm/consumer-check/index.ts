// Compiled by CI against the built packages; never run.
import * as auto from "@structured-world/structured-email-address";
import * as ts from "@structured-world/structured-email-address-ts";
import * as wasm from "@structured-world/structured-email-address-wasm";

export const backends = [auto.parse, ts.parse, wasm.parse];
