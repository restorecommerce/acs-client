/**
 * Unauthenticated means the caller could not be authenticated.
 */
export class Unauthenticated extends Error {
  details: string;
  name: string;
  message: string;
  code: string;
  constructor(details: string, code: string) {
    super();
    this.name = this.constructor.name;
    this.message = 'unauthenticated';
    this.details = details;
    this.code = code;
  }
}

/**
* PermissionDenied indicates the caller does not have permission to
* execute the specified operation.
*/
export class PermissionDenied extends Error {
  details: string;
  name: string;
  message: string;
  code: string;
  constructor(details: string, code: string) {
    super();
    this.name = this.constructor.name;
    this.message = 'permission denied';
    this.details = details;
    this.code = code;
  }
}