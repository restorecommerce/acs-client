export declare enum AuthZAction {
    CREATE = "CREATE",
    READ = "READ",
    MODIFY = "MODIFY",
    DELETE = "DELETE",
    EXECUTE = "EXECUTE",
    DROP = "DROP",
    ALL = "*"
}
export interface AuthZSubject {
    id: string;
    role_associations: RoleAssociation[];
    hierarchical_scopes?: HierarchicalScope[];
}
export interface HierarchicalScope {
    id: string;
    role?: string;
    children?: HierarchicalScope[];
}
export interface Subject {
    id?: string;
    scope?: string;
    role_associations?: RoleAssociation[];
    hierarchical_scopes?: HierarchicalScope[];
    unauthenticated?: boolean;
}
export interface ApiKeyValue {
    value?: string;
}
export interface ApiKey {
    api_key?: ApiKeyValue;
}
export declare enum Decision {
    PERMIT = "PERMIT",
    DENY = "DENY",
    INDETERMINATE = "INDETERMINATE"
}
export interface Resource {
    type: string;
    fields?: string[];
    instance?: any;
    namespace?: string;
}
export interface Target<TSubject, TResource, TAction> {
    subject: TSubject;
    resources: TResource[];
    action: TAction;
}
export interface Request<TTarget, TContext> {
    target: TTarget;
    context: TContext;
}
export interface Response {
    decision: Decision;
}
/**
 * isAllowed Authorization interface
 */
export interface AuthZ<TSubject, TContext = any, TResource = Resource, TAction = AuthZAction> {
    /**
     * Check is the subject is allowed to do an action on a specific resource
     */
    isAllowed(request: Request<Target<TSubject, TResource, TAction>, TContext>): Promise<Decision>;
}
export interface Credentials {
    type: string;
    [key: string]: any;
}
export declare type AuthZTarget = Target<Subject, Resource, AuthZAction>;
export declare type NoAuthTarget = Target<UnauthenticatedData, Resource, AuthZAction>;
export declare type AuthZWhatIsAllowedTarget = Target<Subject, Resource, AuthZAction[]>;
export declare type NoAuthWhatIsAllowedTarget = Target<UnauthenticatedData, Resource, AuthZAction[]>;
export interface AuthZContext {
    security: any;
}
export interface ResourceData {
    id: string;
    meta: MetaInfo;
    [key: string]: any;
}
export interface AuthZRequest extends Request<AuthZTarget, AuthZContext> {
    target: AuthZTarget;
    context: AuthZContext;
}
export interface AuthZResponse extends Response {
    decision: Decision;
    obligation: string;
}
export interface IAuthZ extends AuthZ<AuthZSubject | UnauthenticatedData, AuthZContext, Resource, AuthZAction> {
    whatIsAllowed: (request: Request<AuthZWhatIsAllowedTarget | NoAuthWhatIsAllowedTarget, AuthZContext>) => Promise<PolicySetRQ>;
}
export interface UserCredentials extends Credentials {
    identifier: string;
    password: string;
}
export interface OwnerAttribute {
    id: string;
    value: string;
}
export interface UnauthenticatedContext {
    session: UnauthenticatedSession;
}
export interface UnauthenticatedSession {
    data: UnauthenticatedData;
}
export interface UnauthenticatedData {
    unauthenticated: true;
}
export interface Attribute {
    id: string;
    value: string;
}
export interface RoleAssociation {
    role: string;
    attributes?: Attribute[];
}
export interface MetaInfo {
    created: number;
    modified: number;
    modified_by: string;
    owner: Attribute[];
}
export interface UserScope {
    role_associations: RoleAssociation[];
    scopeOrganization: string;
}
export interface AccessControlObjectInterface {
    id?: string;
    name?: string;
    description?: string;
    target?: AttributeTarget;
    effect?: Effect;
    condition?: string;
}
export interface PolicySetRQ extends AccessControlObjectInterface {
    combining_algorithm: string;
    policies?: PolicyRQ[];
}
export interface PolicyRQ extends AccessControlObjectInterface {
    rules?: RuleRQ[];
    has_rules?: boolean;
    combining_algorithm?: string;
}
export interface RuleRQ extends AccessControlObjectInterface {
}
export interface AttributeTarget {
    subject: Attribute[];
    resources: Attribute[];
    action: Attribute[];
}
export declare enum Effect {
    PERMIT = "PERMIT",
    DENY = "DENY",
    INDETERMINATE = "INDETERMINATE"
}
export interface ACSRequest {
    target: TargetReq;
    context: Context;
}
export interface TargetReq {
    subject: Attribute[];
    resources: Attribute[];
    action: Attribute[];
}
export interface Context {
    subject: any;
    resources: any[];
    security: any;
}
