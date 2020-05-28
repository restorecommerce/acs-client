import { AuthZContext, Attribute, AuthZAction, AuthZTarget, AuthZWhatIsAllowedTarget, PolicySetRQ, IAuthZ, NoAuthTarget, NoAuthWhatIsAllowedTarget, Request, Resource, Decision, Subject } from './interfaces';
export declare type Authorizer = ACSAuthZ;
export declare let authZ: Authorizer;
export declare const createActionTarget: (action: any) => Attribute[];
export declare const createSubjectTarget: (subject: Subject) => Attribute[];
export declare const createResourceTarget: (resources: Resource[], action: AuthZAction | AuthZAction[]) => Attribute[];
export declare const createResourceTargetWhatIsAllowed: (resources: Resource[]) => Attribute[];
export declare class UnAuthZ implements IAuthZ {
    acs: any;
    /**
     *
     * @param acs Access Control Service definition (gRPC)
     */
    constructor(acs: any);
    isAllowed(request: Request<NoAuthTarget, AuthZContext>): Promise<Decision>;
    whatIsAllowed(request: Request<NoAuthWhatIsAllowedTarget, AuthZContext>): Promise<PolicySetRQ>;
}
/**
 * General authorizer. Marshalls data and requests access to the Access Control Service (ACS).
 */
export declare class ACSAuthZ implements IAuthZ {
    acs: any;
    /**
     *
     * @param acs Access Control Service definition (gRPC)
     */
    constructor(acs: any);
    /**
     * Perform request to access-control-srv
     * @param subject
     * @param action
     * @param resource
     */
    isAllowed(request: Request<AuthZTarget, AuthZContext>): Promise<Decision>;
    /**
    * Perform request to access-control-srv
    * @param subject
    * @param action
    * @param resource
    */
    whatIsAllowed(request: Request<AuthZWhatIsAllowedTarget, AuthZContext>): Promise<PolicySetRQ>;
    private encode;
    prepareRequest(request: Request<AuthZTarget | AuthZWhatIsAllowedTarget, AuthZContext>): any;
}
export declare const initAuthZ: (config?: any) => Promise<void | ACSAuthZ>;
