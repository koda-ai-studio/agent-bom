import type { components } from "../api-schema.generated";

export type ApiSchemas = components["schemas"];

/** A generated response envelope whose row fields keep the narrower hand-written row types. */
export type ContractEnvelope<T, Rows> = { [K in keyof T as K extends keyof Rows ? never : K]: T[K] } & Rows;
