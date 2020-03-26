/**
 * Unauthenticated means the caller could not be authenticated.
 */
export declare class Unauthenticated extends Error {
    details: string;
    name: string;
    message: string;
    code: string;
    constructor(details: string, code: string);
}
/**
* PermissionDenied indicates the caller does not have permission to
* execute the specified operation.
*/
export declare class PermissionDenied extends Error {
    details: string;
    name: string;
    message: string;
    code: string;
    constructor(details: string, code: string);
}
