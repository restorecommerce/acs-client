import * as _ from 'lodash';
import {
  ACSContext, UserSessionData, PolicySetRQ,
  UnauthenticatedContext, Resource, Decision
} from './interfaces';
import { AuthZAction } from './interfaces';
import logger from '../logger';
import { errors, cfg } from '../config';
import { buildFilterPermissions } from '../utils';
import { Client } from '@restorecommerce/grpc-client';
import { UnAuthZ } from './authz';
import { Unauthenticated, PermissionDenied } from './errors';


const contextIsUnauthenticated = (object: any): object is UnauthenticatedContext => {
  return !!object && 'session' in object && 'data' in object['session']
    && 'unauthenticated' in object['session']['data'] && object['session']['data']['unauthenticated'];
};

const whatIsAllowed = async (ctx: ACSContext, action: AuthZAction[], resources: Resource[]) => {
  if (contextIsUnauthenticated(ctx)) {
    const grpcConfig = cfg.get('client:acs-srv');
    const acsClient = new Client(grpcConfig, logger);
    const acs = await acsClient.connect();
    return new UnAuthZ(acs).whatIsAllowed({
      target: {
        action, resources, subject: ctx.session.data
      },
      context: {
        security: {}
      }
    });
  } else {
    const user = ctx.session.data as UserSessionData;
    return ctx.authZ.whatIsAllowed({
      context: {
        security: {}
      },
      target: {
        action,
        resources,
        subject: user
      }
    }, user.hierarchical_scope);
  }
};

const isResource = (object: any): object is Resource => {
  return 'type' in object;
};

const isResourceList = (object: any): object is Resource[] => {
  return _.isArray(object) && isResource(object[0]);
};

const isReadRequest = (object: any): object is ReadRequest => {
  return 'entity' in object;
};

export const isAllowed = async (ctx: ACSContext, action: AuthZAction, resources: Resource[]): Promise<Decision> => {
  if (contextIsUnauthenticated(ctx)) {
    const grpcConfig = cfg.get('client:acs-srv');
    const acsClient = new Client(grpcConfig, logger);
    const acs = await acsClient.connect();
    return new UnAuthZ(acs).isAllowed({
      target: {
        action, resources, subject: ctx.session.data
      },
      context: {
        security: {}
      }
    });
  } else {
    let user;
    if (ctx && ctx.session && ctx.session.data) {
      user = ctx.session.data as UserSessionData;
    }

    return ctx.authZ.isAllowed({
      context: {
        security: {}
      },
      target: {
        action,
        resources,
        subject: user
      }
    }, user.hierarchical_scope);
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
 * @param {AuthZAction} action Action to be performed on resource
 * @param {Resource | Resource[] | ReadRequest} request request object either Resource or ReadRequest
 * @param {ACSContext} ctx Context Object containing requester's subject information
 * @returns {Decision | PolicySetRQ}
 */
export const accessRequest = async (action: AuthZAction, request: Resource[] | Resource | ReadRequest,
  ctx: ACSContext): Promise<Decision | PolicySetRQ> => {
  // if apiKey mode is enabled
  if ((ctx as any).req
    && (ctx as any).req.headers
    && (ctx as any).req.headers['authorization']
    && (ctx as any).req.headers['expected-authorization']
    && (ctx as any).req.headers['authorization'] === (ctx as any).req.headers['expected-authorization']) {
    if (action === AuthZAction.CREATE || action === AuthZAction.MODIFY || AuthZAction.DELETE) {
      return Decision.PERMIT;
    } else if (action === AuthZAction.READ) {
      return await whatIsAllowed(ctx as ACSContext, [action], [{
        type: (request as ReadRequest).entity,
        namespace: (request as ReadRequest).namespace
      }]);
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
    if (action === AuthZAction.CREATE || action === AuthZAction.MODIFY || AuthZAction.DELETE) {
      return Decision.PERMIT;
    } else if (action === AuthZAction.READ) {
      return await whatIsAllowed(ctx as ACSContext, [action], [{
        type: (request as ReadRequest).entity,
        namespace: (request as ReadRequest).namespace
      }]);
    }
  }

  if (ctx && ctx.session == null) {
    // user registry
    if (!ctx['authN']) { // user registry
      if (action != AuthZAction.CREATE || isResource(request) && request.type != 'user'
        || isResourceList(request) && request[0].type != 'user') {
        throw new Unauthenticated(errors.USER_NOT_LOGGED_IN.message, errors.USER_NOT_LOGGED_IN.code);
      }
    }
  }

  let resources: any[] = [];
  // for read operations
  if (action == AuthZAction.READ && isReadRequest(request)) {
    const resourceName = request.entity;
    let policySet: PolicySetRQ;
    try {
      // retrieving set of applicable policies/rules from ACS
      // Note: it is assumed that there is only one policy set
      policySet = await whatIsAllowed(ctx as ACSContext, [action], [{
        type: resourceName,
        namespace: (request as ReadRequest).namespace
      }]);
    } catch (err) {
      logger.error('Error calling whatIsAllowed:', { message: err.message });
      throw err;
    }

    // handle case if policySet is empty
    if (_.isEmpty(policySet) && authzEnforced) {
      const msg = `Access not allowed for a request from user ` +
        `${(ctx.session.data as UserSessionData).name} for resource ${resourceName}; ` +
        `the response was INDETERMINATE`;
      const details = 'no matching policy/rule could be found';
      logger.error(msg);
      logger.error('Details:', { details });
      throw new PermissionDenied(msg, errors.ACTION_NOT_ALLOWED.code);
    }

    if (_.isEmpty(policySet) && !authzEnforced) {
      logger.warn(`The Access response was INDETERMIATE for a request from user ` +
        `${(ctx.session.data as UserSessionData).name} for resource ${resourceName} ` +
        `as no matching policy/rule could be found, but since ACS enforcement ` +
        `config is disabled overriding the ACS result`);
    }
    // extend input filter to enforce applicable policies
    const permissionArguments = await buildFilterPermissions(policySet, ctx, request.database);
    if (!permissionArguments && authzEnforced) {
      const msg = `Access not allowed for a request from user ` +
        `${(ctx.session.data as UserSessionData).name} for resource ${resourceName}; ` +
        `the response was DENY`;
      const details = `user does not have access to target scope ${(ctx.session.data as UserSessionData).scope}`;
      logger.error(msg);
      logger.error('Details:', { details });
      throw new PermissionDenied(msg, errors.ACTION_NOT_ALLOWED.code);
    }

    if (!permissionArguments && !authzEnforced) {
      logger.warn(`The Access response was DENY for a request from user ` +
        `${(ctx.session.data as UserSessionData).name} for resource ${resourceName} ` +
        `as user does not have access to target scope ${(ctx.session.data as UserSessionData).scope}, ` +
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

  if (!isResourceList(request) && isResource(request)) {
    request = [request];
  }

  if (isResourceList(request)) {
    resources = request;
  }

  // default deny
  let decision: Decision = Decision.DENY;
  // for write operations
  if (!_.isEmpty(resources) || action == AuthZAction.DELETE) {
    // authorization
    decision = await isAllowed(ctx, action, resources);

    if (decision && decision != Decision.PERMIT && authzEnforced) {
      let details = '';
      if (decision === Decision.INDETERMINATE) {
        details = 'No matching policy / rule was found';
      } else if (decision === Decision.DENY) {
        details = `User does not have access to requested target scope ${(ctx.session.data as UserSessionData).scope}`;
      }
      const msg = `Access not allowed for a request from user ` +
        `${(ctx.session.data as UserSessionData).name} for resource ${resources[0].type}; ` +
        `the response was ${decision}`;
      logger.error(msg);
      logger.error('Details:', { details });
      throw new PermissionDenied(msg, errors.ACTION_NOT_ALLOWED.code);
    }
  }
  if (!authzEnforced && decision && decision != Decision.PERMIT) {
    let details = '';
    if (decision === Decision.INDETERMINATE) {
      details = 'No matching policy / rule was found';
    } else if (decision === Decision.DENY) {
      details = `User does not have access to requested target scope ${(ctx.session.data as UserSessionData).scope}`;
    }
    logger.warn(`Access not allowed for a request from user ` +
      `${(ctx.session.data as UserSessionData).name} for resource ${resources[0].type}; ` +
      `the response was ${decision}`);
    logger.warn(`${details}, Overriding the ACS result as ACS enforce config is disabled`);
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
export const parseResourceList = (resourceList: Array<any>, action: AuthZAction,
  entity: string, ctx: ACSContext, resourceNamespace?: string, fields?: string[]): Resource[] => {
  let userData = {};
  if (ctx.session && ctx.session.data) {
    userData = (ctx.session.data);
  }
  return resourceList.map((resource): Resource => {
    let instance = convertToObject(resource);
    if (action == AuthZAction.CREATE || action == AuthZAction.MODIFY || action == AuthZAction.DELETE) {
      instance = createMetadata(instance, userData);
    }
    return {
      fields: fields || _.keys(instance),
      instance,
      type: entity,
      namespace: resourceNamespace
    };
  });
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
  me?: UserSessionData;
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
