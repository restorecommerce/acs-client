import { PolicySetRQ, Resource, Decision, ACSRequest, Subject, UnauthenticatedData } from './interfaces';
import { AuthZAction } from './interfaces';
import { ACSAuthZ } from './authz';
export declare const isAllowedRequest: (subject: Subject | UnauthenticatedData, resources: Resource[], action: AuthZAction, authZ: ACSAuthZ) => Promise<Decision>;
/**
 * It turns an API request as can be found in typical Web frameworks like express, koa etc.
 * into a proper ACS request. For write operations it uses `isAllowed()` and for read operations
 * it uses `whatIsAllowed()`. For the latter it extends the filter provided in the `ReadRequst`
 * to enforce the applicapble poilicies. The response is `Decision`
 * or policy set reverse query `PolicySetRQ` depending on the requeste operation `isAllowed()` or
 * `whatIsAllowed()` respectively.
 * @param {Subject} subject Contains subject information
 * @param {AuthZAction} action Action to be performed on resource
 * @param {Resource | Resource[] | ReadRequest} request request object either Resource or ReadRequest
 * @param {ACSAuthZ} authZ ACS Authorization Object containing grpc client connection for `access-control-srv`
 * @returns {Decision | PolicySetRQ}
 */
export declare const accessRequest: (subject: Subject | UnauthenticatedData, request: Resource | Resource[] | ReadRequest, action: AuthZAction, authZ: ACSAuthZ) => Promise<Decision | PolicySetRQ>;
/**
 * parses the input resources list and adds entity meta data to object
 * and returns resource list Resource[]
 * @param {Array<any>} resourceList input resources list
 * @param {AuthZAction} action action to be performed on resource
 * @param {string} entity target entity
 * @param {ACSContext} ctx context object
 * @param {string} resourceNamespace name space prefix for resoruce entity
 * @param {string[]} fields input fields
 * @return {Resource[]}
 */
export declare const parseResourceList: (subject: Subject, resourceList: any[], action: AuthZAction, entity: string, resourceNamespace?: string, fields?: string[]) => Resource[];
/**
 * Exposes the isAllowed() api of `access-control-srv` and retruns the response
 * as `Decision`.
 * @param {ACSRequest} request input authorization request
 * @param {ACSContext} ctx Context Object containing requester's subject information
 * @return {Decision} PERMIT or DENY or INDETERMINATE
 */
export declare const isAllowed: (request: ACSRequest, authZ: ACSAuthZ) => Promise<Decision>;
/**
 * Exposes the whatIsAllowed() api of `access-control-srv` and retruns the response
 * a policy set reverse query `PolicySetRQ`
 * @param {ACSRequest} authZRequest input authorization request
 * @param {ACSContext} ctx Context Object containing requester's subject information
 * @return {PolicySetRQ} set of applicalbe policies and rules for the input request
 */
export declare const whatIsAllowed: (request: ACSRequest, authZ: ACSAuthZ) => Promise<PolicySetRQ>;
export interface Output {
    details?: PayloadStatus[];
    error?: OutputError;
}
export interface OutputError {
    message: string;
    code: number;
}
export interface PayloadStatus {
    payload: any;
    status: {
        message: string;
        code: number;
    };
}
export interface LoginResult {
    me?: Subject;
    error?: LoginError;
}
export interface LoginError {
    code: string;
    message: string;
}
export interface ReadRequest {
    entity: string;
    args: QueryArguments;
    database?: string;
    namespace?: string;
}
export interface QueryArguments {
    filter?: any;
    limit?: any;
    sort?: any;
    offset?: any;
}
export interface UserQueryArguments extends QueryArguments {
    user_role: RoleRequest;
}
export interface RoleRequest {
    role: string;
    organizations: string[];
}
export interface FilterType {
    field?: string;
    value?: string;
    operation: Object;
}
