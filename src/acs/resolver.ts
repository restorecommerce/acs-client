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

/**
 *
 * @param action
 * @param ctx
 * @param input Input for query or mutation.
 * @param cb Async operation to be performed. '
 * If cb is set to null and action is 'read', a generic `service.read(input)` is performed.
 * Cb can be useful in business-specific operations or when in need of some field-specific handling.
 */
export async function accessRequest(action: AuthZAction, input: Resource[] | Resource | LoginInput | ReadRequest,
  ctx: any, cb?: Function): Promise<any | LoginResult | UserSessionData | PolicySetRQ> {
  let output = {
    details: [
      {
        payload: null,
        status: {
          message: '',
          code: ''
        }
      }
    ]
  };

  if (ctx.req
    && ctx.req.headers
    && ctx.req.headers['authorization']
    && ctx.req.headers['expected-authorization']
    && ctx.req.headers['authorization'] === ctx.req.headers['expected-authorization']) {
    return cb(input);
  }

  // authentication
  // if no token exists in 'ctx' and user is not attempting to sign in
  if (!cfg.get('authorization:enabled')) {
    if (cb) {
      output = await cb(input);
    }
    return output;
  }
  if (action === 'session') {
    return cb ? cb() : null;
  } else if (action != 'login' && ctx && ctx.session == null) {
    // user registry
    if (!ctx['authN']) { // user registry
      if (action != 'create' || isResource(input) && input.type != 'user.User'
        || isResourceList(input) && input[0].type != 'user.User') {
        output.details[0].status.message = errors.USER_NOT_LOGGED_IN.message;
        output.details[0].status.code = errors.USER_NOT_LOGGED_IN.code;
        return output;
      }
    }
  }
  else if ((action == 'search' && isReadRequest(input)) || (action == 'GET' && isReadRequest(input))) {
    const resourceName = input.entity;
    let policySet: PolicySetRQ;
    try {
      policySet = await whatIsAllowed(ctx as ACSContext, ['read'], [{ type: resourceName }]);
      if (action === 'search' || action === 'GET') {
        output = await cb(policySet);
        return output;
      }
    } catch (err) {
      logger.error('Error calling whatIsAllowed:', { message: err.message });
      return {
        error: {
          code: [err.code],
          message: err.message
        }
      };
    }
  }

  let resources: any[] = [];
  if (action == 'read' && isReadRequest(input)) {
    const resourceName = input.entity;
    let policySet: PolicySetRQ;

    try {
      // retrieving set of applicable policies/rules from ACS
      // Note: it is assumed that there is only one policy set
      policySet = await whatIsAllowed(ctx as ACSContext, [action], [{ type: resourceName }]);
    } catch (err) {
      logger.error('Error calling whatIsAllowed:', { message: err.message });
      return {
        error: {
          code: [err.code],
          message: err.message
        }
      };
    }

    // handle case if policySet is empty
    if (_.isEmpty(policySet)) {
      const msg = `Access not allowed for a request from user ${(ctx.session.data as UserSessionData).name}; the response was INDETERMINATE`;
      logger.verbose(msg);
      output.details[0].status.message = msg;
      output.details[0].status.code = errors.ACTION_NOT_ALLOWED.code;
      return output;
    }

    const permissionArguments = await buildFilterPermissions(policySet, ctx, input.database);
    if (!permissionArguments) {
      return {
        details: [] // no resource retrieved
      };
    }

    if (input.database && input.database === 'postgres') {
      try {
        output = await cb(permissionArguments);
      } catch (err) {
        logger.error('Error while running query', { err });
        output.details[0].status.message = errors.SYSTEM_ERROR.message;
        output.details[0].status.code = errors.SYSTEM_ERROR.code;
      }
      return output;
    }

    const finalFilter = { $and: [] };
    if (!_.isEmpty(input.args.filter)) {
      let filterArgs = _.cloneDeep(input.args.filter);
      if (!_.isArray(filterArgs)) {
        filterArgs = [filterArgs];
      }
      let payload = {};
      filterArgs && filterArgs.length && filterArgs.forEach(element => {
        const { value, field, operation } = element;
        payload[field] = { ...payload[field], [`$${operation}`]: value };
      });
      finalFilter.$and.push(payload);
    }
    if (!_.isEmpty(permissionArguments.filter)) {
      finalFilter.$and.push(permissionArguments.filter);
    }

    permissionArguments.filter = finalFilter;
    delete input.args.filter;
    _.merge(permissionArguments, input.args, permissionArguments);
    if (!cb) {
      output.details[0].status.message = errors.MISSING_OPERATION.message;
      output.details[0].status.code = errors.MISSING_OPERATION.code;
      return output;
    }

    try {
      output = await cb(permissionArguments);
    } catch (err) {
      logger.error('Error while running query', { err });
      output.details[0].status.message = errors.SYSTEM_ERROR.message;
      output.details[0].status.code = errors.SYSTEM_ERROR.code;
    }

    if (!output) {
      return;
    }
    return output;
  }

  if (!isResourceList(input) && isResource(input)) {
    input = [input];
  }

  if (isResourceList(input)) {
    resources = input;
  }

  if (action === 'permissions' && ctx.session && ctx.session.data) {
    resources = input as Resource[];
    const actionList: AuthZAction[] = ['create', 'read', 'modify', 'delete', 'execute'];
    let response: any = {};
    try {
      response = await whatIsAllowed(ctx as ACSContext, actionList, resources);
    } catch (err) {
      logger.error('Error calling whatIsAllowed :', { message: err.message });
      response.error = {};
      response.error.message = [err.message];
      response.error.code = [err.code];
    }
    return response;
  }

  if (!_.isEmpty(resources) || action == 'execute' || action == 'delete') {
    try {
      // authorization
      let allowed = await isAllowed(ctx as any, action, resources);

      if (allowed && allowed.decision != Decision.PERMIT) {
        const msg = `Access not allowed for a request from user ${(ctx.session.data as UserSessionData).name}; the response was ${allowed.decision}`;
        logger.verbose(msg);

        // output.details = null;
        output.details[0].status.message = msg;
        output.details[0].status.code = errors.ACTION_NOT_ALLOWED.code;
        return output;
      }
    } catch (err) {
      logger.verbose('Error while calling ACS', { err });
      return {
        error: {
          code: [errors.ACTION_NOT_ALLOWED.code],
          message: ['An error occurred while requesting authorization']
        }
      };
    }
  }

  if (cb) {
    output = await cb(input);
  } else {
    output.details[0].status.message = errors.MISSING_OPERATION.message;
    output.details[0].status.code = errors.MISSING_OPERATION.code;
  }
  return output;
}

export async function isAllowed(ctx: any, action: AuthZAction,
  resources: Resource[]) {
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
}

async function whatIsAllowed(ctx: ACSContext, action: AuthZAction[],
  resources: Resource[]) {
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
    });
  }
}

export function parseResourceList(resourceList: Array<any>, action: AuthZAction,
  entity: string, ctx: ACSContext, fields?: string[]): Resource[] {
  let userData = {};
  if (ctx.session && ctx.session.data) {
    userData = (ctx.session.data);
  }
  return resourceList.map((resource): Resource => {
    let instance = convertToObject(resource);
    if (action == 'create' || action == 'delete' || action == 'modify') {
      instance = createMetadata(instance, userData);
    }
    return {
      fields: fields || _.keys(instance),
      instance,
      type: entity
    };
  });
}

function createMetadata(resource: any, userData: any): any {
  const ownerAttributes: any[] = _.cloneDeep(resource.owner) || [];
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
}

function convertToObject(resources: any | any[]): any | any[] {
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
}

export interface Output {
  details?: string[];
  error?: OutputError;
}

export interface OutputError {
  details: PayloadStatus[];
}

export interface PayloadStatus {
  payload: any;
  status: {
    message: string,
    code: number;
  };
}

export interface LoginInput {
  identifier: string;
  password: string;
  rememberMe: boolean;
  ctx: ACSContext;
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

function isResource(object: any): object is Resource {
  return 'type' in object;
}

function isResourceList(object: any): object is Resource[] {
  return _.isArray(object) && isResource(object[0]);
}

function isReadRequest(object: any): object is ReadRequest {
  return 'entity' in object;
}

function contextIsUnauthenticated(object: any): object is UnauthenticatedContext {
  return !!object && 'session' in object && 'data' in object['session']
    && 'unauthenticated' in object['session']['data'] && object['session']['data']['unauthenticated'];
}
