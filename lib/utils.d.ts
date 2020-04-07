import { RoleAssociation, UserScope, Subject, PolicySetRQ } from './acs/interfaces';
import { QueryArguments, UserQueryArguments } from './acs/resolver';
export declare const reduceRoleAssociations: (roleAssociations: RoleAssociation[], scopeID: string) => Promise<UserScope>;
export declare const handleError: (err: any) => any;
export declare const buildFilterPermissions: (policySet: PolicySetRQ, subject: Subject, database?: string) => QueryArguments | UserQueryArguments;
