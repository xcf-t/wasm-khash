/* tslint:disable */
/* eslint-disable */
/**
* @param {Uint8Array} data
* @returns {string}
*/
export function execute_zip_analyzer(data: Uint8Array): string;
/**
* @param {Uint8Array} data
* @returns {string}
*/
export function execute_rar_analyzer(data: Uint8Array): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly execute_zip_analyzer: (a: number, b: number, c: number) => void;
  readonly execute_rar_analyzer: (a: number, b: number, c: number) => void;
  readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
  readonly __wbindgen_malloc: (a: number) => number;
  readonly __wbindgen_free: (a: number, b: number) => void;
}

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {InitInput | Promise<InitInput>} module_or_path
*
* @returns {Promise<InitOutput>}
*/
export default function init (module_or_path?: InitInput | Promise<InitInput>): Promise<InitOutput>;