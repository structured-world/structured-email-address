// What every package exports besides its own `init` and parsing functions.

export { EmailAddressError, isGlobalScope, type ParseOutcome, type Parser } from "./api.js";
export type {
  AddressLiteral,
  CasePolicy,
  Config,
  DomainCheck,
  DomainScope,
  DotPolicy,
  EmailAddress,
  ErrorKind,
  IpScope,
  LiteralScope,
  ProviderRule,
  PslLoadOptions,
  Strictness,
  SubaddressPolicy,
  TsInitOptions,
  WasmInitOptions,
} from "./types.js";
