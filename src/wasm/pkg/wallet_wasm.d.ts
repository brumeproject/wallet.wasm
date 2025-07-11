/* tslint:disable */
/* eslint-disable */
export function sha1(data: Memory): Memory;
export function base16_encode_lower(bytes: Memory): string;
export function base16_encode_upper(bytes: Memory): string;
export function base16_decode_mixed(text: string): Memory;
export function base16_decode_lower(text: string): Memory;
export function base16_decode_upper(text: string): Memory;
export function keccak256(data: Memory): Memory;
export function base64_encode_padded(bytes: Memory): string;
export function base64_decode_padded(text: string): Memory;
export function base64_encode_unpadded(bytes: Memory): string;
export function base64_decode_unpadded(text: string): Memory;
export function base64url_encode_padded(bytes: Memory): string;
export function base64url_decode_padded(text: string): Memory;
export function base64url_encode_unpadded(bytes: Memory): string;
export function base64url_decode_unpadded(text: string): Memory;
export function ripemd160(data: Memory): Memory;
export function base58_encode(bytes: Memory): string;
export function base58_decode(text: string): Memory;
export class ChaCha20Cipher {
  [Symbol.dispose](): void;
  constructor(key: Memory, nonce: Memory);
  seek(position: number): void;
  apply_keystream(memory: Memory): void;
}
export class ChaCha20Poly1305Cipher {
  [Symbol.dispose](): void;
  constructor(key: Memory);
  encrypt(message: Memory, nonce: Memory): Memory;
  decrypt(message: Memory, nonce: Memory): Memory;
}
export class Ed25519Signature {
  [Symbol.dispose](): void;
  constructor(bytes: Memory);
  static from_bytes(bytes: Memory): Ed25519Signature;
  to_bytes(): Memory;
  r_bytes(): Memory;
  s_bytes(): Memory;
}
export class Ed25519SigningKey {
  [Symbol.dispose](): void;
  constructor();
  static random(): Ed25519SigningKey;
  static from_bytes(bytes: Memory): Ed25519SigningKey;
  static from_keypair_bytes(bytes: Memory): Ed25519SigningKey;
  to_bytes(): Memory;
  to_keypair_bytes(): Memory;
  verifying_key(): Ed25519VerifyingKey;
  sign(bytes: Memory): Ed25519Signature;
  verify(bytes: Memory, signature: Ed25519Signature): boolean;
  verify_strict(bytes: Memory, signature: Ed25519Signature): boolean;
}
export class Ed25519VerifyingKey {
  [Symbol.dispose](): void;
  constructor(bytes: Memory);
  static from_bytes(bytes: Memory): Ed25519VerifyingKey;
  is_weak(): boolean;
  to_bytes(): Memory;
  verify(bytes: Memory, signature: Ed25519Signature): boolean;
  verify_strict(bytes: Memory, signature: Ed25519Signature): boolean;
}
export class Keccak256Hasher {
  [Symbol.dispose](): void;
  constructor();
  clone(): Keccak256Hasher;
  update(data: Memory): void;
  finalize(): Memory;
}
export class Memory {
  [Symbol.dispose](): void;
/**
* @param {Uint8Array} inner
*/
  constructor(inner: Uint8Array);
/**
* @returns {number}
*/
  ptr(): number;
/**
* @returns {number}
*/
  len(): number;
/**
* @returns {Uint8Array}
*/
  get bytes(): Uint8Array;
}
export class NetworkMixin {
  [Symbol.dispose](): void;
  constructor(version_memory: Memory, address_memory: Memory, nonce_memory: Memory);
  generate(minimum_memory: Memory): NetworkSecret;
  verify_proof(proof_memory: Memory): Memory;
  verify_secret(secret_memory: Memory): Memory;
  verify_proofs(proofs_memory: Memory): Memory;
  verify_secrets(secrets_memory: Memory): Memory;
}
export class NetworkSecret {
  private constructor();
  [Symbol.dispose](): void;
  to_secret(): Memory;
  to_proof(): Memory;
  to_value(): Memory;
}
export class Ripemd160Hasher {
  [Symbol.dispose](): void;
  constructor();
  clone(): Ripemd160Hasher;
  update(data: Memory): void;
  finalize(): Memory;
}
export class Secp256k1SignatureAndRecovery {
  [Symbol.dispose](): void;
  constructor(signature: Memory, recovery: number);
  static from_bytes(input: Memory): Secp256k1SignatureAndRecovery;
  to_bytes(): Memory;
}
export class Secp256k1SigningKey {
  [Symbol.dispose](): void;
  constructor();
  static random(): Secp256k1SigningKey;
  static from_bytes(input: Memory): Secp256k1SigningKey;
  to_bytes(): Memory;
  verifying_key(): Secp256k1VerifyingKey;
  sign_prehash_recoverable(hashed: Memory): Secp256k1SignatureAndRecovery;
}
export class Secp256k1VerifyingKey {
  private constructor();
  [Symbol.dispose](): void;
  static from_sec1_bytes(input: Memory): Secp256k1VerifyingKey;
  static recover_from_prehash(hashed: Memory, signature: Secp256k1SignatureAndRecovery): Secp256k1VerifyingKey;
  to_sec1_compressed_bytes(): Memory;
  to_sec1_uncompressed_bytes(): Memory;
}
export class Sha1Hasher {
  [Symbol.dispose](): void;
  constructor();
  clone(): Sha1Hasher;
  update(data: Memory): void;
  finalize(): Memory;
}
export class X25519PublicKey {
  [Symbol.dispose](): void;
  constructor(bytes: Memory);
  static from_bytes(bytes: Memory): X25519PublicKey;
  to_bytes(): Memory;
}
export class X25519SharedSecret {
  private constructor();
  [Symbol.dispose](): void;
  to_bytes(): Memory;
  was_contributory(): boolean;
}
export class X25519StaticSecret {
  [Symbol.dispose](): void;
  constructor();
  static from_bytes(bytes: Memory): X25519StaticSecret;
  to_bytes(): Memory;
  diffie_hellman(other: X25519PublicKey): X25519SharedSecret;
  to_public(): X25519PublicKey;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly __wbg_x25519publickey_free: (a: number, b: number) => void;
  readonly x25519publickey_from_bytes: (a: number) => [number, number, number];
  readonly x25519publickey_to_bytes: (a: number) => number;
  readonly x25519publickey_new: (a: number) => [number, number, number];
  readonly __wbg_x25519sharedsecret_free: (a: number, b: number) => void;
  readonly x25519sharedsecret_to_bytes: (a: number) => number;
  readonly x25519sharedsecret_was_contributory: (a: number) => number;
  readonly __wbg_x25519staticsecret_free: (a: number, b: number) => void;
  readonly x25519staticsecret_random: () => number;
  readonly x25519staticsecret_from_bytes: (a: number) => [number, number, number];
  readonly x25519staticsecret_to_bytes: (a: number) => number;
  readonly x25519staticsecret_diffie_hellman: (a: number, b: number) => number;
  readonly x25519staticsecret_to_public: (a: number) => number;
  readonly sha1: (a: number) => number;
  readonly __wbg_sha1hasher_free: (a: number, b: number) => void;
  readonly sha1hasher_new: () => number;
  readonly sha1hasher_clone: (a: number) => number;
  readonly sha1hasher_update: (a: number, b: number) => void;
  readonly sha1hasher_finalize: (a: number) => number;
  readonly __wbg_secp256k1signatureandrecovery_free: (a: number, b: number) => void;
  readonly secp256k1signatureandrecovery_new: (a: number, b: number) => [number, number, number];
  readonly secp256k1signatureandrecovery_from_bytes: (a: number) => [number, number, number];
  readonly secp256k1signatureandrecovery_to_bytes: (a: number) => number;
  readonly __wbg_secp256k1signingkey_free: (a: number, b: number) => void;
  readonly secp256k1signingkey_new: () => number;
  readonly secp256k1signingkey_from_bytes: (a: number) => [number, number, number];
  readonly secp256k1signingkey_to_bytes: (a: number) => number;
  readonly secp256k1signingkey_verifying_key: (a: number) => number;
  readonly secp256k1signingkey_sign_prehash_recoverable: (a: number, b: number) => [number, number, number];
  readonly secp256k1signingkey_random: () => number;
  readonly __wbg_secp256k1verifyingkey_free: (a: number, b: number) => void;
  readonly secp256k1verifyingkey_from_sec1_bytes: (a: number) => [number, number, number];
  readonly secp256k1verifyingkey_recover_from_prehash: (a: number, b: number) => [number, number, number];
  readonly secp256k1verifyingkey_to_sec1_compressed_bytes: (a: number) => number;
  readonly secp256k1verifyingkey_to_sec1_uncompressed_bytes: (a: number) => number;
  readonly ripemd160: (a: number) => number;
  readonly __wbg_ripemd160hasher_free: (a: number, b: number) => void;
  readonly ripemd160hasher_new: () => number;
  readonly ripemd160hasher_clone: (a: number) => number;
  readonly ripemd160hasher_update: (a: number, b: number) => void;
  readonly ripemd160hasher_finalize: (a: number) => number;
  readonly __wbg_networksecret_free: (a: number, b: number) => void;
  readonly networksecret_to_secret: (a: number) => number;
  readonly networksecret_to_proof: (a: number) => number;
  readonly networksecret_to_value: (a: number) => number;
  readonly __wbg_networkmixin_free: (a: number, b: number) => void;
  readonly networkmixin_new: (a: number, b: number, c: number) => number;
  readonly networkmixin_generate: (a: number, b: number) => number;
  readonly networkmixin_verify_proof: (a: number, b: number) => number;
  readonly networkmixin_verify_secret: (a: number, b: number) => number;
  readonly networkmixin_verify_proofs: (a: number, b: number) => number;
  readonly networkmixin_verify_secrets: (a: number, b: number) => number;
  readonly keccak256: (a: number) => number;
  readonly __wbg_keccak256hasher_free: (a: number, b: number) => void;
  readonly keccak256hasher_new: () => number;
  readonly keccak256hasher_clone: (a: number) => number;
  readonly keccak256hasher_update: (a: number, b: number) => void;
  readonly keccak256hasher_finalize: (a: number) => number;
  readonly __wbg_ed25519signingkey_free: (a: number, b: number) => void;
  readonly ed25519signingkey_new: () => number;
  readonly ed25519signingkey_from_bytes: (a: number) => [number, number, number];
  readonly ed25519signingkey_from_keypair_bytes: (a: number) => [number, number, number];
  readonly ed25519signingkey_to_bytes: (a: number) => number;
  readonly ed25519signingkey_to_keypair_bytes: (a: number) => number;
  readonly ed25519signingkey_verifying_key: (a: number) => number;
  readonly ed25519signingkey_sign: (a: number, b: number) => number;
  readonly ed25519signingkey_verify: (a: number, b: number, c: number) => number;
  readonly ed25519signingkey_verify_strict: (a: number, b: number, c: number) => number;
  readonly ed25519signingkey_random: () => number;
  readonly __wbg_ed25519verifyingkey_free: (a: number, b: number) => void;
  readonly ed25519verifyingkey_from_bytes: (a: number) => [number, number, number];
  readonly ed25519verifyingkey_is_weak: (a: number) => number;
  readonly ed25519verifyingkey_to_bytes: (a: number) => number;
  readonly ed25519verifyingkey_verify: (a: number, b: number, c: number) => number;
  readonly ed25519verifyingkey_verify_strict: (a: number, b: number, c: number) => number;
  readonly ed25519verifyingkey_new: (a: number) => [number, number, number];
  readonly __wbg_ed25519signature_free: (a: number, b: number) => void;
  readonly ed25519signature_from_bytes: (a: number) => [number, number, number];
  readonly ed25519signature_to_bytes: (a: number) => number;
  readonly ed25519signature_r_bytes: (a: number) => number;
  readonly ed25519signature_s_bytes: (a: number) => number;
  readonly ed25519signature_new: (a: number) => [number, number, number];
  readonly __wbg_chacha20cipher_free: (a: number, b: number) => void;
  readonly chacha20cipher_new: (a: number, b: number) => [number, number, number];
  readonly chacha20cipher_seek: (a: number, b: number) => [number, number];
  readonly chacha20cipher_apply_keystream: (a: number, b: number) => [number, number];
  readonly __wbg_chacha20poly1305cipher_free: (a: number, b: number) => void;
  readonly chacha20poly1305cipher_new: (a: number) => [number, number, number];
  readonly chacha20poly1305cipher_encrypt: (a: number, b: number, c: number) => [number, number, number];
  readonly chacha20poly1305cipher_decrypt: (a: number, b: number, c: number) => [number, number, number];
  readonly base64_encode_padded: (a: number) => [number, number];
  readonly base64_decode_padded: (a: number, b: number) => [number, number, number];
  readonly base64_encode_unpadded: (a: number) => [number, number];
  readonly base64_decode_unpadded: (a: number, b: number) => [number, number, number];
  readonly base64url_encode_padded: (a: number) => [number, number];
  readonly base64url_decode_padded: (a: number, b: number) => [number, number, number];
  readonly base64url_encode_unpadded: (a: number) => [number, number];
  readonly base64url_decode_unpadded: (a: number, b: number) => [number, number, number];
  readonly base58_encode: (a: number) => [number, number];
  readonly base58_decode: (a: number, b: number) => [number, number, number];
  readonly base16_encode_lower: (a: number) => [number, number];
  readonly base16_encode_upper: (a: number) => [number, number];
  readonly base16_decode_mixed: (a: number, b: number) => [number, number, number];
  readonly base16_decode_lower: (a: number, b: number) => [number, number, number];
  readonly base16_decode_upper: (a: number, b: number) => [number, number, number];
  readonly __wbg_memory_free: (a: number, b: number) => void;
  readonly memory_new: (a: number, b: number) => number;
  readonly memory_ptr: (a: number) => number;
  readonly memory_len: (a: number) => number;
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __externref_table_alloc: () => number;
  readonly __wbindgen_export_2: WebAssembly.Table;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __externref_table_dealloc: (a: number) => void;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
