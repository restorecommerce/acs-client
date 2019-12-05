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
 * Receives an access request and constructs the Target request object for
 * access-control-srv and returns a decision for access request or call back
 * function with permission arguments for inference
 * @param {AuthZAction} action Action to be performed on resource
 * @param ctx
 * @param {Resource | Resource[] | ReadRequest} input Input for query or mutation
 * @param {Function} cb Async operation to be performed
 * cb used for business-specific operations or when in need of some field-specific handling
 */
export async function accessRequest(action: AuthZAction, input: Resource[] | Resource | ReadRequest,
  ctx: ACSContext, cb?: Function): Promise<any | LoginResult | UserSessionData | PolicySetRQ> {
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

  if ((ctx as any).req
    && (ctx as any).req.headers
    && (ctx as any).req.headers['authorization']
    && (ctx as any).req.headers['expected-authorization']
    && (ctx as any).req.headers['authorization'] === (ctx as any).req.headers['expected-authorization']) {
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
  if (ctx && ctx.session == null) {
    // user registry
    if (!ctx['authN']) { // user registry
      if (action != AuthZAction.CREATE || isResource(input) && input.type != 'user.User'
        || isResourceList(input) && input[0].type != 'user.User') {
        output.details[0].status.message = errors.USER_NOT_LOGGED_IN.message;
        output.details[0].status.code = errors.USER_NOT_LOGGED_IN.code;
        return output;
      }
    }
  }

  let resources: any[] = [];
  if (action == AuthZAction.READ && isReadRequest(input)) {
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

  if (!_.isEmpty(resources) || action == AuthZAction.DELETE) {
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

/**
 * parses the input resources list and adds meta data to object and returns Resource[]
 * @param {Array<any>} resourceList input resources list
 * @param {AuthZAction} action action to be performed on resource
 * @param {string} entity target entity
 * @param {ACSContext} ctx context object
 * @param {string[]} fields input fields
 * @return {Resource[]}
 */
export function parseResourceList(resourceList: Array<any>, action: AuthZAction,
  entity: string, ctx: ACSContext, fields?: string[]): Resource[] {
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
      type: entity
    };
  });
}

function createMetadata(resource: any, userData: any): any {
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
