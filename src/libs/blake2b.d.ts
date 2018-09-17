export declare function blake2bInit(outlen: any, key: any): {
    b: Uint8Array;
    h: Uint32Array;
    t: number;
    c: number;
    outlen: any;
};
export declare function blake2bUpdate(ctx: any, input: any): void;
export declare function blake2bFinal(ctx: any): Uint8Array;
export declare function blake2b(input: any, key: any, outlen: any): Uint8Array;
export declare function blake2bHex(input: any, key: any, outlen: any): any;
