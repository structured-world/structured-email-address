import { contract } from "../../shared/test/contract.js";
import * as wasm from "./index.js";

contract("wasm", { ...wasm, init: () => wasm.init() });
