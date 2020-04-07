import * as _ from 'lodash';
import {
  PolicySetRQ, UnauthenticatedContext, Resource, Decision,
  ACSRequest, Subject, UnauthenticatedData, ApiKey
} from './interfaces';
import { AuthZAction } from './interfaces';
import logger from '../logger';
import { errors, cfg } from '../config';
import { buildFilterPermissions } from '../utils';
import { Client } from '@restorecommerce/grpc-client';
import { UnAuthZ, ACSAuthZ } from './authz';
import { Unauthenticated, PermissionDenied } from './errors';


const subjectIsUnauthenticated = (subject: any): subject is UnauthenticatedContext => {
  return !!subject
    && 'unauthenticated' in subject && subject['unauthenticated'];
};

const whatIsAllowedRequest = async (subject: Subject | ApiKey,
  resources: Resource[], action: AuthZAction[], authZ: ACSAuthZ) => {
  if (subjectIsUnauthenticated(subject)) {
    const grpcConfig = cfg.get('client:acs-srv');
    const acsClient = new Client(grpcConfig, logger);
    const acs = await acsClient.connect();
    return new UnAuthZ(acs).whatIsAllowed({
      target: {
        action, resources, subject: (subject as UnauthenticatedData)
      },
      context: {
        security: {}
      }
    });
  } else {
    return authZ.whatIsAllowed({
      context: {
        security: {}
      },
      target: {
        action,
        resources,
        subject: (subject as Subject)
      }
    }, (subject as Subject).hierarchical_scopes);
  }
};

const isReadRequest = (object: any): object is ReadRequest => {
  return 'entity' in object;
};

export const isAllowedRequest = async (subject: Subject | UnauthenticatedData,
  resources: Resource[], action: AuthZAction, authZ: ACSAuthZ): Promise<Decision> => {
  if (subjectIsUnauthenticated(subject)) {
    const grpcConfig = cfg.get('client:acs-srv');
    const acsClient = new Client(grpcConfig, logger);
    const acs = await acsClient.connect();
    return new UnAuthZ(acs).isAllowed({
      target: {
        action, resources, subject: (subject as UnauthenticatedData)
      },
      context: {
        security: {}
      }
    });
  } else {
    return authZ.isAllowed({
      context: {
        security: {}
      },
      target: {
        action,
        resources,
        subject
      }
    }, (subject as Subject).hierarchical_scopes);
  }
};

const createMetadata = (resource: any, userData: any): any => {
  let ownerAttributes = [];
  if (resource.meta && resource.meta.owner) {
    ownerAttributes = _.cloneDeep(resource.meta.owner);
  } else if (resource.owner) {
    ownerAttributes = _.cloneDeep(resource.owner);
  }
  const urns = cfg.get('authorization:urns');

  let ownUser = false;
  let foundEntity = false;
  for (let attribute of ownerAttributes) {
    if (attribute.id == urns.ownerIndicatoryEntity && attribute.value == urns.user) {
      foundEntity = true;
    } else if (attribute.id == urns.ownerInstance && attribute.value == userData.id && foundEntity) {
      ownUser = true;
      break;
    }
  }

  if (resource.orgKey) {
    ownerAttributes.push(
      {
        id: urns.ownerIndicatoryEntity,
        value: urns.organization
      },
      {
        id: urns.ownerInstance,
        value: resource.orgKey
      });
  }

  if (!ownUser && !!userData.id) {
    ownerAttributes.push(
      {
        id: urns.ownerIndicatoryEntity,
        value: urns.user
      },
      {
        id: urns.ownerInstance,
        value: userData.id
      });
  }

  delete resource.owner;

  if (!resource.meta) {
    resource.meta = {};
  }
  resource.meta.modified_by = userData.id;
  resource.meta.owner = ownerAttributes;
  return resource;
};

const convertToObject = (resources: any | any[]): any | any[] => {
  if (!_.isArray(resources)) {
    return JSON.parse(JSON.stringify(resources));
  }
  // GraphQL object is a pseudo-object;
  // when processing its fields, we get an exception from gRPC
  // so this fix is to sanitize all fields
  return resources.map((resource) => {
    const stringified = JSON.stringify(resource);
    return JSON.parse(stringified);
  });
};

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
export const accessRequest = async (subject: Subject | ApiKey,
  request: Resource[] | Resource | ReadRequest, action: AuthZAction,
  authZ: ACSAuthZ): Promise<Decision | PolicySetRQ> => {
  // TODO: add command to sync dynamic apikey
  let reqApiKey = (subject as ApiKey).api_key;
  // if apiKey mode is enabled
  if (reqApiKey) {
    let configuredApiKey = cfg.get('authentication:apiKey');
    if (configuredApiKey && configuredApiKey === reqApiKey ) {
      if (action === AuthZAction.CREATE || action === AuthZAction.MODIFY ||
        action === AuthZAction.DELETE || action === AuthZAction.EXECUTE) {
        return Decision.PERMIT;
      } else if (action === AuthZAction.READ) {
        // make auth ctx uanth since authorization is disabled
        if (!subject) {
          subject = { unauthenticated: true };
        }
        return await whatIsAllowedRequest(subject, [{
          type: (request as ReadRequest).entity,
          namespace: (request as ReadRequest).namespace
        }], [action], authZ);
      }
    }
  }
  let authzEnabled = cfg.get('authorization:enabled');
  let authzEnforced = cfg.get('authorization:enforce');
  // by default if the config for authorization enabling and enforcement is missing
  // enable it by default (true)
  if (authzEnabled === undefined) {
    authzEnabled = true;
  }
  if (authzEnforced === undefined) {
    authzEnforced = true;
  }
  // if authorization is disabled
  if (!authzEnabled) {
    // if action is write
    if (action === AuthZAction.CREATE || action === AuthZAction.MODIFY ||
      action === AuthZAction.DELETE || action === AuthZAction.EXECUTE) {
      return Decision.PERMIT;
    } else if (action === AuthZAction.READ) {
      // make auth ctx uanth since authorization is disabled
      if (!subject) {
        subject = { unauthenticated: true };
      }
      return await whatIsAllowedRequest(subject, [{
        type: (request as ReadRequest).entity,
        namespace: (request as ReadRequest).namespace
      }], [action], authZ);
    }
  }

  if (!subject) {
    throw new Unauthenticated(errors.USER_NOT_LOGGED_IN.message, errors.USER_NOT_LOGGED_IN.code);
  }

  let resources: any[] = [];
  let requestingUserName_ID = (subject as Subject).id;
  let targetScope = (subject as Subject).scope;
  // for read operations
  if (action == AuthZAction.READ && isReadRequest(request)
    // for action create or modify with read request to get policySetRQ
    || ((action == AuthZAction.CREATE || action == AuthZAction.MODIFY) && isReadRequest(request))) {
    const resourceName = request.entity;
    let policySet: PolicySetRQ;
    try {
      // retrieving set of applicable policies/rules from ACS
      // Note: it is assumed that there is only one policy set
      policySet = await whatIsAllowedRequest(subject, [{
        type: resourceName,
        namespace: (request as ReadRequest).namespace
      }], [action], authZ);
    } catch (err) {
      logger.error('Error calling whatIsAllowed:', { message: err.message });
      throw err;
    }

    // handle case if policySet is empty
    if (_.isEmpty(policySet) && authzEnforced) {
      const msg = `Access not allowed for request with subject:${requestingUserName_ID}, ` +
        `resource:${resourceName}, action:${action}, target_scope:${targetScope}; the response was INDETERMINATE`;
      const details = 'no matching policy/rule could be found';
      logger.verbose(msg);
      logger.verbose('Details:', { details });
      throw new PermissionDenied(msg, errors.ACTION_NOT_ALLOWED.code);
    }

    if (_.isEmpty(policySet) && !authzEnforced) {
      logger.verbose(`The Access response was INDETERMIATE for a request with subject:` +
        `${requestingUserName_ID}, resource:${resourceName}, action:${action}, target_scope:${targetScope} ` +
        `as no matching policy/rule could be found, but since ACS enforcement ` +
        `config is disabled overriding the ACS result`);
    }
    // extend input filter to enforce applicable policies
    const permissionArguments = buildFilterPermissions(policySet, subject as Subject, request.database);
    if (!permissionArguments && authzEnforced) {
      const msg = `Access not allowed for request with subject:${requestingUserName_ID}, ` +
        `resource:${resourceName}, action:${action}, target_scope:${targetScope}; the response was DENY`;
      const details = `Subject:${requestingUserName_ID} does not have access to target scope ${targetScope}}`;
      logger.verbose(msg);
      logger.verbose('Details:', { details });
      throw new PermissionDenied(msg, errors.ACTION_NOT_ALLOWED.code);
    }

    if (!permissionArguments && !authzEnforced) {
      logger.verbose(`The Access response was DENY for a request from subject:${requestingUserName_ID}, ` +
        `resource:${resourceName}, action:${action}, target_scope:${targetScope}, ` +
        `but since ACS enforcement config is disabled overriding the ACS result`);
    }

    if (request.args && request.args.filter) {
      for (let filter of request.args.filter) {
        if (!_.isArray(permissionArguments.filter)) {
          permissionArguments.filter = [filter];
        }
        permissionArguments.filter.push(filter);
      }
    }
    Object.assign(request.args, permissionArguments);
    return policySet;
  }

  if (!_.isArray(request)) {
    resources = [request];
  } else {
    resources = request;
  }

  // default deny
  let decision: Decision = Decision.DENY;
  // for write operations
  if (!_.isEmpty(resources) || action == AuthZAction.DELETE || action == AuthZAction.EXECUTE) {
    // authorization
    decision = await isAllowedRequest(subject as Subject, resources, action, authZ);

    if (decision && decision != Decision.PERMIT && authzEnforced) {
      let details = '';
      if (decision === Decision.INDETERMINATE) {
        details = 'No matching policy / rule was found';
      } else if (decision === Decision.DENY) {
        details = `Subject:${requestingUserName_ID} does not have access to requested target scope ${targetScope}`;
      }
      const msg = `Access not allowed for request with subject:${requestingUserName_ID}, ` +
        `resource:${resources[0].type}, action:${action}, target_scope:${targetScope}; the response was ${decision}`;
      logger.verbose(msg);
      logger.verbose('Details:', { details });
      throw new PermissionDenied(msg, errors.ACTION_NOT_ALLOWED.code);
    }
  }
  if (!authzEnforced && decision && decision != Decision.PERMIT) {
    let details = '';
    if (decision === Decision.INDETERMINATE) {
      details = 'No matching policy / rule was found';
    } else if (decision === Decision.DENY) {
      details = `Subject:${requestingUserName_ID} does not have access to requested target scope ${targetScope}`;
    }
    logger.verbose(`Access not allowed for request with subject:${requestingUserName_ID}, ` +
      `resource:${resources[0].type}, action:${action}, target_scope:${targetScope}; the response was ${decision}`);
    logger.verbose(`${details}, Overriding the ACS result as ACS enforce config is disabled`);
    decision = Decision.PERMIT;
  }
  return decision;
};

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
export const parseResourceList = (subject: Subject, resourceList: Array<any>,
  action: AuthZAction, entity: string, resourceNamespace?: string, fields?: string[]): Resource[] => {
  return resourceList.map((resource): Resource => {
    let instance = convertToObject(resource);
    if (action == AuthZAction.CREATE || action == AuthZAction.MODIFY || action == AuthZAction.DELETE) {
      instance = createMetadata(instance, subject);
    }
    return {
      fields: fields || _.keys(instance),
      instance,
      type: entity,
      namespace: resourceNamespace
    };
  });
};

/**
 * Exposes the isAllowed() api of `access-control-srv` and retruns the response
 * as `Decision`.
 * @param {ACSRequest} request input authorization request
 * @param {ACSContext} ctx Context Object containing requester's subject information
 * @return {Decision} PERMIT or DENY or INDETERMINATE
 */
export const isAllowed = async (request: ACSRequest,
  authZ: ACSAuthZ): Promise<Decision> => {
  const response = await authZ.acs.isAllowed(request);

  if (_.isEmpty(response) || _.isEmpty(response.data)) {
    console.log(response.error);
    logger.error('Unexpected empty response from ACS');
  } else if (response.data.decision) {
    return response.data.decision;
  }

  if (response.error) {
    logger.verbose('Error while requesting authorization to ACS...', { error: response.error.message });
    throw new Error('Error while requesting authorization to ACS');
  }

  return Decision.DENY;
};

/**
 * Exposes the whatIsAllowed() api of `access-control-srv` and retruns the response
 * a policy set reverse query `PolicySetRQ`
 * @param {ACSRequest} authZRequest input authorization request
 * @param {ACSContext} ctx Context Object containing requester's subject information
 * @return {PolicySetRQ} set of applicalbe policies and rules for the input request
 */
export const whatIsAllowed = async (request: ACSRequest,
  authZ: ACSAuthZ): Promise<PolicySetRQ> => {
  const response = await authZ.acs.whatIsAllowed(request);
  if (_.isEmpty(response) || _.isEmpty(response.data)) {
    logger.error('Unexpected empty response from ACS');
  }

  if (response.error) {
    logger.verbose('Error while requesting authorization to ACS...', { error: response.error.message });
    throw new Error('Error while requesting authorization to ACS');
  }
  return (response.data.policy_sets || []).length > 0 ? response.data.policy_sets[0] : {};
};

export interface Output {
  details?: PayloadStatus[];
  error?: OutputError;
}

// error: {
//   code: [err.code],
//   message: err.message
// }
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
  role: string; // role ID
  organizations: string[]; //
}

export interface FilterType {
  field?: string;
  value?: string;
  operation: Object;
}
