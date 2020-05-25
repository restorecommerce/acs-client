import * as _ from 'lodash';
import {
  ACSContext, UserSessionData, PolicySetRQ,
  UnauthenticatedContext, Resource, Decision, ACSRequest
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

const whatIsAllowedRequest = async (ctx: ACSContext, action: AuthZAction[], resources: Resource[]) => {
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

export const isAllowedRequest = async (ctx: ACSContext, action: AuthZAction, resources: Resource[]): Promise<Decision> => {
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
    let user: UserSessionData = {};
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
  if (ctx && (ctx as any).req
    && (ctx as any).req.headers
    && (ctx as any).req.headers['authorization']
    && (ctx as any).req.headers['expected-authorization']
    && (ctx as any).req.headers['authorization'] === (ctx as any).req.headers['expected-authorization']) {
    if (action === AuthZAction.CREATE || action === AuthZAction.MODIFY ||
      action === AuthZAction.DELETE || action === AuthZAction.EXECUTE) {
      return Decision.PERMIT;
    } else if (action === AuthZAction.READ) {
      // make auth ctx uanth since authorization is disabled
      if (!ctx || !ctx.session || !ctx.session.data) {
        ctx = Object.assign({}, ctx, { session: { data: { unauthenticated: true } } });
      }
      return await whatIsAllowedRequest(ctx as ACSContext, [action], [{
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
    if (action === AuthZAction.CREATE || action === AuthZAction.MODIFY ||
      action === AuthZAction.DELETE || action === AuthZAction.EXECUTE) {
      return Decision.PERMIT;
    } else if (action === AuthZAction.READ) {
      // make auth ctx uanth since authorization is disabled
      if (!ctx || !ctx.session || !ctx.session.data) {
        ctx = Object.assign({}, ctx, { session: { data: { unauthenticated: true } } });
      }
      return await whatIsAllowedRequest(ctx as ACSContext, [action], [{
        type: (request as ReadRequest).entity,
        namespace: (request as ReadRequest).namespace
      }]);
    }
  }

  if (!ctx || (ctx && ctx.session == null)) {
    throw new Unauthenticated(errors.USER_NOT_LOGGED_IN.message, errors.USER_NOT_LOGGED_IN.code);
  }

  let resources: any[] = [];
  let requestingUserName_ID = '';
  let targetScope;
  if (ctx && ctx.session && ctx.session.data) {
    requestingUserName_ID = ctx.session.data.name ? ctx.session.data.name : ctx.session.data.id;
    targetScope = ctx.session.data.scope;
  }
  // for read operations
  if (action == AuthZAction.READ && isReadRequest(request)
    // for action create or modify with read request to get policySetRQ
    || ((action == AuthZAction.CREATE || action == AuthZAction.MODIFY) && isReadRequest(request))) {
    const resourceName = request.entity;
    let policySet: PolicySetRQ;
    try {
      // retrieving set of applicable policies/rules from ACS
      // Note: it is assumed that there is only one policy set
      policySet = await whatIsAllowedRequest(ctx as ACSContext, [action], [{
        type: resourceName,
        namespace: (request as ReadRequest).namespace
      }]);
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
    const permissionArguments = buildFilterPermissions(policySet, ctx, request.database);
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

  if (!isResourceList(request) && isResource(request)) {
    request = [request];
  }

  if (isResourceList(request)) {
    resources = request;
  }

  // default deny
  let decision: Decision = Decision.DENY;
  // for write operations
  if (!_.isEmpty(resources) || action == AuthZAction.DELETE || action == AuthZAction.EXECUTE) {
    // authorization
    decision = await isAllowedRequest(ctx, action, resources);

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
 * Exposes the isAllowed() api of `access-control-srv` and retruns the response
 * as `Decision`.
 * @param {ACSRequest} request input authorization request
 * @param {ACSContext} ctx Context Object containing requester's subject information
 * @return {Decision} PERMIT or DENY or INDETERMINATE
 */
export const isAllowed = async (request: ACSRequest,
  ctx: ACSContext): Promise<Decision> => {
  const response = await ctx.authZ.acs.isAllowed(request);

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
  ctx: ACSContext): Promise<PolicySetRQ> => {
  const response = await ctx.authZ.acs.whatIsAllowed(request);
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
