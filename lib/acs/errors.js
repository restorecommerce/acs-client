"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
/**
 * Unauthenticated means the caller could not be authenticated.
 */
class Unauthenticated extends Error {
    constructor(details, code) {
        super();
        this.name = this.constructor.name;
        this.message = 'unauthenticated';
        this.details = details;
        this.code = code;
    }
}
exports.Unauthenticated = Unauthenticated;
/**
* PermissionDenied indicates the caller does not have permission to
* execute the specified operation.
*/
class PermissionDenied extends Error {
    constructor(details, code) {
        super();
        this.name = this.constructor.name;
        this.message = 'permission denied';
        this.details = details;
        this.code = code;
    }
}
exports.PermissionDenied = PermissionDenied;
