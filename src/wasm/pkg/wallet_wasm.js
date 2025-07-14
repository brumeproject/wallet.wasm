let wasm;

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_export_2.set(idx, obj);
    return idx;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

const cachedTextDecoder = (typeof TextDecoder !== 'undefined' ? new TextDecoder('utf-8', { ignoreBOM: true, fatal: true }) : { decode: () => { throw Error('TextDecoder not available') } } );

if (typeof TextDecoder !== 'undefined') { cachedTextDecoder.decode(); };

let cachedUint8ArrayMemory0 = null;

function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

let WASM_VECTOR_LEN = 0;

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function _assertClass(instance, klass) {
    if (!(instance instanceof klass)) {
        throw new Error(`expected instance of ${klass.name}`);
    }
}
/**
 * @param {Memory} data
 * @returns {Memory}
 */
export function sha1(data) {
    _assertClass(data, Memory);
    const ret = wasm.sha1(data.__wbg_ptr);
    return Memory.__wrap(ret);
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_export_2.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}
/**
 * @param {Memory} bytes
 * @returns {string}
 */
export function base16_encode_lower(bytes) {
    let deferred1_0;
    let deferred1_1;
    try {
        _assertClass(bytes, Memory);
        const ret = wasm.base16_encode_lower(bytes.__wbg_ptr);
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

/**
 * @param {Memory} bytes
 * @returns {string}
 */
export function base16_encode_upper(bytes) {
    let deferred1_0;
    let deferred1_1;
    try {
        _assertClass(bytes, Memory);
        const ret = wasm.base16_encode_upper(bytes.__wbg_ptr);
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

const cachedTextEncoder = (typeof TextEncoder !== 'undefined' ? new TextEncoder('utf-8') : { encode: () => { throw Error('TextEncoder not available') } } );

const encodeString = (typeof cachedTextEncoder.encodeInto === 'function'
    ? function (arg, view) {
    return cachedTextEncoder.encodeInto(arg, view);
}
    : function (arg, view) {
    const buf = cachedTextEncoder.encode(arg);
    view.set(buf);
    return {
        read: arg.length,
        written: buf.length
    };
});

function passStringToWasm0(arg, malloc, realloc) {

    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }

    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = encodeString(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}
/**
 * @param {string} text
 * @returns {Memory}
 */
export function base16_decode_mixed(text) {
    const ptr0 = passStringToWasm0(text, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.base16_decode_mixed(ptr0, len0);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return Memory.__wrap(ret[0]);
}

/**
 * @param {string} text
 * @returns {Memory}
 */
export function base16_decode_lower(text) {
    const ptr0 = passStringToWasm0(text, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.base16_decode_lower(ptr0, len0);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return Memory.__wrap(ret[0]);
}

/**
 * @param {string} text
 * @returns {Memory}
 */
export function base16_decode_upper(text) {
    const ptr0 = passStringToWasm0(text, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.base16_decode_upper(ptr0, len0);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return Memory.__wrap(ret[0]);
}

/**
 * @param {Memory} data
 * @returns {Memory}
 */
export function keccak256(data) {
    _assertClass(data, Memory);
    const ret = wasm.keccak256(data.__wbg_ptr);
    return Memory.__wrap(ret);
}

/**
 * @param {Memory} data
 * @returns {Memory}
 */
export function ripemd160(data) {
    _assertClass(data, Memory);
    const ret = wasm.ripemd160(data.__wbg_ptr);
    return Memory.__wrap(ret);
}

/**
 * @param {Memory} bytes
 * @returns {string}
 */
export function base58_encode(bytes) {
    let deferred1_0;
    let deferred1_1;
    try {
        _assertClass(bytes, Memory);
        const ret = wasm.base58_encode(bytes.__wbg_ptr);
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

/**
 * @param {string} text
 * @returns {Memory}
 */
export function base58_decode(text) {
    const ptr0 = passStringToWasm0(text, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.base58_decode(ptr0, len0);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return Memory.__wrap(ret[0]);
}

const ChaCha20CipherFinalization = true
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_chacha20cipher_free(ptr >>> 0, 1));

export class ChaCha20Cipher {

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        ChaCha20CipherFinalization;
        return ptr;
    }

    [Symbol.dispose]() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_chacha20cipher_free(ptr, 0);
    }
    /**
     * @param {Memory} key
     * @param {Memory} nonce
     */
    constructor(key, nonce) {
        _assertClass(key, Memory);
        _assertClass(nonce, Memory);
        const ret = wasm.chacha20cipher_new(key.__wbg_ptr, nonce.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        this.__wbg_ptr = ret[0] >>> 0;
        ChaCha20CipherFinalization;
        return this;
    }
    /**
     * @param {number} position
     */
    seek(position) {
        const ret = wasm.chacha20cipher_seek(this.__wbg_ptr, position);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * @param {Memory} memory
     */
    apply_keystream(memory) {
        _assertClass(memory, Memory);
        const ret = wasm.chacha20cipher_apply_keystream(this.__wbg_ptr, memory.__wbg_ptr);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
}

const ChaCha20Poly1305CipherFinalization = true
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_chacha20poly1305cipher_free(ptr >>> 0, 1));

export class ChaCha20Poly1305Cipher {

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        ChaCha20Poly1305CipherFinalization;
        return ptr;
    }

    [Symbol.dispose]() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_chacha20poly1305cipher_free(ptr, 0);
    }
    /**
     * @param {Memory} key
     */
    constructor(key) {
        _assertClass(key, Memory);
        const ret = wasm.chacha20poly1305cipher_new(key.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        this.__wbg_ptr = ret[0] >>> 0;
        ChaCha20Poly1305CipherFinalization;
        return this;
    }
    /**
     * @param {Memory} message
     * @param {Memory} nonce
     * @returns {Memory}
     */
    encrypt(message, nonce) {
        _assertClass(message, Memory);
        _assertClass(nonce, Memory);
        const ret = wasm.chacha20poly1305cipher_encrypt(this.__wbg_ptr, message.__wbg_ptr, nonce.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return Memory.__wrap(ret[0]);
    }
    /**
     * @param {Memory} message
     * @param {Memory} nonce
     * @returns {Memory}
     */
    decrypt(message, nonce) {
        _assertClass(message, Memory);
        _assertClass(nonce, Memory);
        const ret = wasm.chacha20poly1305cipher_decrypt(this.__wbg_ptr, message.__wbg_ptr, nonce.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return Memory.__wrap(ret[0]);
    }
}

const Keccak256HasherFinalization = true
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_keccak256hasher_free(ptr >>> 0, 1));

export class Keccak256Hasher {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(Keccak256Hasher.prototype);
        obj.__wbg_ptr = ptr;
        Keccak256HasherFinalization;
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        Keccak256HasherFinalization;
        return ptr;
    }

    [Symbol.dispose]() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_keccak256hasher_free(ptr, 0);
    }
    constructor() {
        const ret = wasm.keccak256hasher_new();
        this.__wbg_ptr = ret >>> 0;
        Keccak256HasherFinalization;
        return this;
    }
    /**
     * @returns {Keccak256Hasher}
     */
    clone() {
        const ret = wasm.keccak256hasher_clone(this.__wbg_ptr);
        return Keccak256Hasher.__wrap(ret);
    }
    /**
     * @param {Memory} data
     */
    update(data) {
        _assertClass(data, Memory);
        wasm.keccak256hasher_update(this.__wbg_ptr, data.__wbg_ptr);
    }
    /**
     * @returns {Memory}
     */
    finalize() {
        const ret = wasm.keccak256hasher_finalize(this.__wbg_ptr);
        return Memory.__wrap(ret);
    }
}

const MemoryFinalization = true
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_memory_free(ptr >>> 0, 1));

export class Memory {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(Memory.prototype);
        obj.__wbg_ptr = ptr;
        MemoryFinalization;
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        this.__wbg_ptr0 = 0;
        this.__wbg_len0 = 0;
        MemoryFinalization;
        return ptr;
    }

    [Symbol.dispose]() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_memory_free(ptr, 0);
    }
    /**
    * @param {Uint8Array} inner
    */
    constructor(inner) {
        const ptr0 = passArray8ToWasm0(inner, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.memory_new(ptr0, len0);
        this.__wbg_ptr = ret >>> 0;
        this.__wbg_ptr0 = ptr0 >>> 0;
        this.__wbg_len0 = len0 >>> 0;
        MemoryFinalization;
        return this;
    }
    /**
    * @returns {number}
    */
    ptr() {
        const ret = wasm.memory_ptr(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
    * @returns {number}
    */
    len() {
        const ret = wasm.memory_len(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
    * @returns {number}
    */
    get ptr0() {
        return this.__wbg_ptr0 ??= this.ptr();
    }
    /**
    * @returns {number}
    */
    get len0() {
        return this.__wbg_len0 ??= this.len();
    }
    /**
    * @returns {Uint8Array}
    */
    get bytes() {
        return getUint8ArrayMemory0().subarray(this.ptr0, this.ptr0 + this.len0);
    }
}

const NetworkMixinFinalization = true
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_networkmixin_free(ptr >>> 0, 1));

export class NetworkMixin {

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        NetworkMixinFinalization;
        return ptr;
    }

    [Symbol.dispose]() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_networkmixin_free(ptr, 0);
    }
    /**
     * @param {Memory} version_memory
     * @param {Memory} address_memory
     * @param {Memory} nonce_memory
     */
    constructor(version_memory, address_memory, nonce_memory) {
        _assertClass(version_memory, Memory);
        _assertClass(address_memory, Memory);
        _assertClass(nonce_memory, Memory);
        const ret = wasm.networkmixin_new(version_memory.__wbg_ptr, address_memory.__wbg_ptr, nonce_memory.__wbg_ptr);
        this.__wbg_ptr = ret >>> 0;
        NetworkMixinFinalization;
        return this;
    }
    /**
     * @param {Memory} minimum_memory
     * @returns {NetworkSecret}
     */
    generate(minimum_memory) {
        _assertClass(minimum_memory, Memory);
        const ret = wasm.networkmixin_generate(this.__wbg_ptr, minimum_memory.__wbg_ptr);
        return NetworkSecret.__wrap(ret);
    }
    /**
     * @param {Memory} proof_memory
     * @returns {Memory}
     */
    verify_proof(proof_memory) {
        _assertClass(proof_memory, Memory);
        const ret = wasm.networkmixin_verify_proof(this.__wbg_ptr, proof_memory.__wbg_ptr);
        return Memory.__wrap(ret);
    }
    /**
     * @param {Memory} secret_memory
     * @returns {Memory}
     */
    verify_secret(secret_memory) {
        _assertClass(secret_memory, Memory);
        const ret = wasm.networkmixin_verify_secret(this.__wbg_ptr, secret_memory.__wbg_ptr);
        return Memory.__wrap(ret);
    }
    /**
     * @param {Memory} proofs_memory
     * @returns {Memory}
     */
    verify_proofs(proofs_memory) {
        _assertClass(proofs_memory, Memory);
        const ret = wasm.networkmixin_verify_proofs(this.__wbg_ptr, proofs_memory.__wbg_ptr);
        return Memory.__wrap(ret);
    }
    /**
     * @param {Memory} secrets_memory
     * @returns {Memory}
     */
    verify_secrets(secrets_memory) {
        _assertClass(secrets_memory, Memory);
        const ret = wasm.networkmixin_verify_secrets(this.__wbg_ptr, secrets_memory.__wbg_ptr);
        return Memory.__wrap(ret);
    }
}

const NetworkSecretFinalization = true
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_networksecret_free(ptr >>> 0, 1));

export class NetworkSecret {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(NetworkSecret.prototype);
        obj.__wbg_ptr = ptr;
        NetworkSecretFinalization;
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        NetworkSecretFinalization;
        return ptr;
    }

    [Symbol.dispose]() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_networksecret_free(ptr, 0);
    }
    /**
     * @returns {Memory}
     */
    to_secret() {
        const ret = wasm.networksecret_to_secret(this.__wbg_ptr);
        return Memory.__wrap(ret);
    }
    /**
     * @returns {Memory}
     */
    to_proof() {
        const ret = wasm.networksecret_to_proof(this.__wbg_ptr);
        return Memory.__wrap(ret);
    }
    /**
     * @returns {Memory}
     */
    to_value() {
        const ret = wasm.networksecret_to_value(this.__wbg_ptr);
        return Memory.__wrap(ret);
    }
}

const Ripemd160HasherFinalization = true
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_ripemd160hasher_free(ptr >>> 0, 1));

export class Ripemd160Hasher {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(Ripemd160Hasher.prototype);
        obj.__wbg_ptr = ptr;
        Ripemd160HasherFinalization;
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        Ripemd160HasherFinalization;
        return ptr;
    }

    [Symbol.dispose]() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_ripemd160hasher_free(ptr, 0);
    }
    constructor() {
        const ret = wasm.ripemd160hasher_new();
        this.__wbg_ptr = ret >>> 0;
        Ripemd160HasherFinalization;
        return this;
    }
    /**
     * @returns {Ripemd160Hasher}
     */
    clone() {
        const ret = wasm.ripemd160hasher_clone(this.__wbg_ptr);
        return Ripemd160Hasher.__wrap(ret);
    }
    /**
     * @param {Memory} data
     */
    update(data) {
        _assertClass(data, Memory);
        wasm.ripemd160hasher_update(this.__wbg_ptr, data.__wbg_ptr);
    }
    /**
     * @returns {Memory}
     */
    finalize() {
        const ret = wasm.ripemd160hasher_finalize(this.__wbg_ptr);
        return Memory.__wrap(ret);
    }
}

const Secp256k1SignatureAndRecoveryFinalization = true
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_secp256k1signatureandrecovery_free(ptr >>> 0, 1));

export class Secp256k1SignatureAndRecovery {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(Secp256k1SignatureAndRecovery.prototype);
        obj.__wbg_ptr = ptr;
        Secp256k1SignatureAndRecoveryFinalization;
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        Secp256k1SignatureAndRecoveryFinalization;
        return ptr;
    }

    [Symbol.dispose]() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_secp256k1signatureandrecovery_free(ptr, 0);
    }
    /**
     * @param {Memory} signature
     * @param {number} recovery
     */
    constructor(signature, recovery) {
        _assertClass(signature, Memory);
        const ret = wasm.secp256k1signatureandrecovery_new(signature.__wbg_ptr, recovery);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        this.__wbg_ptr = ret[0] >>> 0;
        Secp256k1SignatureAndRecoveryFinalization;
        return this;
    }
    /**
     * @param {Memory} input
     * @returns {Secp256k1SignatureAndRecovery}
     */
    static from_bytes(input) {
        _assertClass(input, Memory);
        const ret = wasm.secp256k1signatureandrecovery_from_bytes(input.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return Secp256k1SignatureAndRecovery.__wrap(ret[0]);
    }
    /**
     * @returns {Memory}
     */
    to_bytes() {
        const ret = wasm.secp256k1signatureandrecovery_to_bytes(this.__wbg_ptr);
        return Memory.__wrap(ret);
    }
}

const Secp256k1SigningKeyFinalization = true
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_secp256k1signingkey_free(ptr >>> 0, 1));

export class Secp256k1SigningKey {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(Secp256k1SigningKey.prototype);
        obj.__wbg_ptr = ptr;
        Secp256k1SigningKeyFinalization;
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        Secp256k1SigningKeyFinalization;
        return ptr;
    }

    [Symbol.dispose]() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_secp256k1signingkey_free(ptr, 0);
    }
    constructor() {
        const ret = wasm.secp256k1signingkey_new();
        this.__wbg_ptr = ret >>> 0;
        Secp256k1SigningKeyFinalization;
        return this;
    }
    /**
     * @returns {Secp256k1SigningKey}
     */
    static random() {
        const ret = wasm.secp256k1signingkey_new();
        return Secp256k1SigningKey.__wrap(ret);
    }
    /**
     * @param {Memory} input
     * @returns {Secp256k1SigningKey}
     */
    static from_bytes(input) {
        _assertClass(input, Memory);
        const ret = wasm.secp256k1signingkey_from_bytes(input.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return Secp256k1SigningKey.__wrap(ret[0]);
    }
    /**
     * @returns {Memory}
     */
    to_bytes() {
        const ret = wasm.secp256k1signingkey_to_bytes(this.__wbg_ptr);
        return Memory.__wrap(ret);
    }
    /**
     * @returns {Secp256k1VerifyingKey}
     */
    verifying_key() {
        const ret = wasm.secp256k1signingkey_verifying_key(this.__wbg_ptr);
        return Secp256k1VerifyingKey.__wrap(ret);
    }
    /**
     * @param {Memory} hashed
     * @returns {Secp256k1SignatureAndRecovery}
     */
    sign_prehash_recoverable(hashed) {
        _assertClass(hashed, Memory);
        const ret = wasm.secp256k1signingkey_sign_prehash_recoverable(this.__wbg_ptr, hashed.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return Secp256k1SignatureAndRecovery.__wrap(ret[0]);
    }
}

const Secp256k1VerifyingKeyFinalization = true
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_secp256k1verifyingkey_free(ptr >>> 0, 1));

export class Secp256k1VerifyingKey {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(Secp256k1VerifyingKey.prototype);
        obj.__wbg_ptr = ptr;
        Secp256k1VerifyingKeyFinalization;
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        Secp256k1VerifyingKeyFinalization;
        return ptr;
    }

    [Symbol.dispose]() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_secp256k1verifyingkey_free(ptr, 0);
    }
    /**
     * @param {Memory} input
     * @returns {Secp256k1VerifyingKey}
     */
    static from_sec1_bytes(input) {
        _assertClass(input, Memory);
        const ret = wasm.secp256k1verifyingkey_from_sec1_bytes(input.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return Secp256k1VerifyingKey.__wrap(ret[0]);
    }
    /**
     * @param {Memory} hashed
     * @param {Secp256k1SignatureAndRecovery} signature
     * @returns {Secp256k1VerifyingKey}
     */
    static recover_from_prehash(hashed, signature) {
        _assertClass(hashed, Memory);
        _assertClass(signature, Secp256k1SignatureAndRecovery);
        const ret = wasm.secp256k1verifyingkey_recover_from_prehash(hashed.__wbg_ptr, signature.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return Secp256k1VerifyingKey.__wrap(ret[0]);
    }
    /**
     * @returns {Memory}
     */
    to_sec1_compressed_bytes() {
        const ret = wasm.secp256k1verifyingkey_to_sec1_compressed_bytes(this.__wbg_ptr);
        return Memory.__wrap(ret);
    }
    /**
     * @returns {Memory}
     */
    to_sec1_uncompressed_bytes() {
        const ret = wasm.secp256k1verifyingkey_to_sec1_uncompressed_bytes(this.__wbg_ptr);
        return Memory.__wrap(ret);
    }
}

const Sha1HasherFinalization = true
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_sha1hasher_free(ptr >>> 0, 1));

export class Sha1Hasher {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(Sha1Hasher.prototype);
        obj.__wbg_ptr = ptr;
        Sha1HasherFinalization;
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        Sha1HasherFinalization;
        return ptr;
    }

    [Symbol.dispose]() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_sha1hasher_free(ptr, 0);
    }
    constructor() {
        const ret = wasm.sha1hasher_new();
        this.__wbg_ptr = ret >>> 0;
        Sha1HasherFinalization;
        return this;
    }
    /**
     * @returns {Sha1Hasher}
     */
    clone() {
        const ret = wasm.sha1hasher_clone(this.__wbg_ptr);
        return Sha1Hasher.__wrap(ret);
    }
    /**
     * @param {Memory} data
     */
    update(data) {
        _assertClass(data, Memory);
        wasm.sha1hasher_update(this.__wbg_ptr, data.__wbg_ptr);
    }
    /**
     * @returns {Memory}
     */
    finalize() {
        const ret = wasm.sha1hasher_finalize(this.__wbg_ptr);
        return Memory.__wrap(ret);
    }
}

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);

            } catch (e) {
                if (module.headers.get('Content-Type') != 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else {
                    throw e;
                }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);

    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };

        } else {
            return instance;
        }
    }
}

function __wbg_get_imports() {
    const imports = {};
    imports.wbg = {};
    imports.wbg.__wbg_buffer_aa30bbb65cb44323 = function(arg0) {
        const ret = arg0.buffer;
        return ret;
    };
    imports.wbg.__wbg_call_41c7efaf6b1182f8 = function() { return handleError(function (arg0, arg1, arg2) {
        const ret = arg0.call(arg1, arg2);
        return ret;
    }, arguments) };
    imports.wbg.__wbg_call_c45d13337ffb12ac = function() { return handleError(function (arg0, arg1) {
        const ret = arg0.call(arg1);
        return ret;
    }, arguments) };
    imports.wbg.__wbg_crypto_574e78ad8b13b65f = function(arg0) {
        const ret = arg0.crypto;
        return ret;
    };
    imports.wbg.__wbg_getRandomValues_b8f5dbd5f3995a9e = function() { return handleError(function (arg0, arg1) {
        arg0.getRandomValues(arg1);
    }, arguments) };
    imports.wbg.__wbg_globalThis_856ff24a65e13540 = function() { return handleError(function () {
        const ret = globalThis.globalThis;
        return ret;
    }, arguments) };
    imports.wbg.__wbg_global_fc813a897a497d26 = function() { return handleError(function () {
        const ret = global.global;
        return ret;
    }, arguments) };
    imports.wbg.__wbg_msCrypto_a61aeb35a24c1329 = function(arg0) {
        const ret = arg0.msCrypto;
        return ret;
    };
    imports.wbg.__wbg_new_db41cf29086ce106 = function(arg0) {
        const ret = new Uint8Array(arg0);
        return ret;
    };
    imports.wbg.__wbg_newnoargs_29f93ce2db72cd07 = function(arg0, arg1) {
        const ret = new Function(getStringFromWasm0(arg0, arg1));
        return ret;
    };
    imports.wbg.__wbg_newwithbyteoffsetandlength_c8ea72df7687880b = function(arg0, arg1, arg2) {
        const ret = new Uint8Array(arg0, arg1 >>> 0, arg2 >>> 0);
        return ret;
    };
    imports.wbg.__wbg_newwithlength_60b9d756f80003a6 = function(arg0) {
        const ret = new Uint8Array(arg0 >>> 0);
        return ret;
    };
    imports.wbg.__wbg_node_905d3e251edff8a2 = function(arg0) {
        const ret = arg0.node;
        return ret;
    };
    imports.wbg.__wbg_process_dc0fbacc7c1c06f7 = function(arg0) {
        const ret = arg0.process;
        return ret;
    };
    imports.wbg.__wbg_randomFillSync_ac0988aba3254290 = function() { return handleError(function (arg0, arg1) {
        arg0.randomFillSync(arg1);
    }, arguments) };
    imports.wbg.__wbg_require_60cc747a6bc5215a = function() { return handleError(function () {
        const ret = module.require;
        return ret;
    }, arguments) };
    imports.wbg.__wbg_self_799f153b0b6e0183 = function() { return handleError(function () {
        const ret = self.self;
        return ret;
    }, arguments) };
    imports.wbg.__wbg_set_e97d203fd145cdae = function(arg0, arg1, arg2) {
        arg0.set(arg1, arg2 >>> 0);
    };
    imports.wbg.__wbg_subarray_a984c21c3cf98bbb = function(arg0, arg1, arg2) {
        const ret = arg0.subarray(arg1 >>> 0, arg2 >>> 0);
        return ret;
    };
    imports.wbg.__wbg_versions_c01dfd4722a88165 = function(arg0) {
        const ret = arg0.versions;
        return ret;
    };
    imports.wbg.__wbg_window_cd65fa4478648b49 = function() { return handleError(function () {
        const ret = window.window;
        return ret;
    }, arguments) };
    imports.wbg.__wbindgen_error_new = function(arg0, arg1) {
        const ret = new Error(getStringFromWasm0(arg0, arg1));
        return ret;
    };
    imports.wbg.__wbindgen_init_externref_table = function() {
        const table = wasm.__wbindgen_export_2;
        const offset = table.grow(4);
        table.set(0, undefined);
        table.set(offset + 0, undefined);
        table.set(offset + 1, null);
        table.set(offset + 2, true);
        table.set(offset + 3, false);
        ;
    };
    imports.wbg.__wbindgen_is_function = function(arg0) {
        const ret = typeof(arg0) === 'function';
        return ret;
    };
    imports.wbg.__wbindgen_is_object = function(arg0) {
        const val = arg0;
        const ret = typeof(val) === 'object' && val !== null;
        return ret;
    };
    imports.wbg.__wbindgen_is_string = function(arg0) {
        const ret = typeof(arg0) === 'string';
        return ret;
    };
    imports.wbg.__wbindgen_is_undefined = function(arg0) {
        const ret = arg0 === undefined;
        return ret;
    };
    imports.wbg.__wbindgen_memory = function() {
        const ret = wasm.memory;
        return ret;
    };
    imports.wbg.__wbindgen_string_new = function(arg0, arg1) {
        const ret = getStringFromWasm0(arg0, arg1);
        return ret;
    };
    imports.wbg.__wbindgen_throw = function(arg0, arg1) {
        throw new Error(getStringFromWasm0(arg0, arg1));
    };

    return imports;
}

function __wbg_init_memory(imports, memory) {

}

function __wbg_finalize_init(instance, module) {
    wasm = instance.exports;
    __wbg_init.__wbindgen_wasm_module = module;
    cachedUint8ArrayMemory0 = null;


    wasm.__wbindgen_start();
    return wasm;
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (typeof module !== 'undefined') {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();

    __wbg_init_memory(imports);

    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }

    const instance = new WebAssembly.Instance(module, imports);

    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (typeof module_or_path !== 'undefined') {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (typeof module_or_path === 'undefined') {
        throw new Error();
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    __wbg_init_memory(imports);

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync };
export default __wbg_init;
