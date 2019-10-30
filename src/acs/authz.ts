import * as _ from 'lodash';
import {
  AuthZContext, Attribute,
  AuthZAction, AuthZTarget, UserSessionData,
  AuthZWhatIsAllowedTarget, PolicySetRQ, IAuthZ,
  NoAuthTarget, UnauthenticatedData, NoAuthWhatIsAllowedTarget, RoleAssociation,
  HierarchicalScope, Request, Resource, Response, Decision
} from './interfaces';
import { Client } from '@restorecommerce/grpc-client';
import { cfg } from '../config';
import logger from '../logger';

export declare type Authorizer = ACSAuthZ;
export let authZ: Authorizer;
const urns = cfg.get('authorization:urns');



export class UnAuthZ implements IAuthZ {
  acs: any;
  /**
   *
   * @param acs Access Control Service definition (gRPC)
   */
  constructor(acs: any) {
    this.acs = acs;
  }

  async isAllowed(request: Request<NoAuthTarget, AuthZContext>): Promise<Response> {
    const authZRequest = {
      target: {
        action: createActionTarget(request.target.action),
        subject: createSubjectTarget(request.target.subject),
        resources: createResourceTarget(request.target.resources, request.target.action)
      },
      context: request.context
    };

    const response = await this.acs.isAllowed(authZRequest);

    if (_.isEmpty(response) || _.isEmpty(response.data)) {
      console.log(response.error);
      logger.error('Unexpected empty response from ACS');
    } else if (response.data.decision) {
      return {
        decision: response.data.decision as Decision
      };
    }

    if (response.error) {
      logger.verbose('Error while requesting authorization to ACS...', { error: response.error.message });
      throw new Error('Error while requesting authorization to ACS');
    }

    return {
      decision: Decision.DENY
    };

  }
  async whatIsAllowed(request: Request<NoAuthWhatIsAllowedTarget, AuthZContext>): Promise<PolicySetRQ> {
    const authZRequest = {
      target: {
        action: createActionTarget(request.target.action),
        subject: createSubjectTarget(request.target.subject),
        resources: createResourceTarget(request.target.resources, request.target.action)
      },
      context: request.context
    };

    const response = await this.acs.whatIsAllowed(authZRequest);
    if (_.isEmpty(response) || _.isEmpty(response.data)) {
      logger.error('Unexpected empty response from ACS');
    }

    if (response.error) {
      logger.verbose('Error while requesting authorization to ACS...', { error: response.error.message });
      throw new Error('Error while requesting authorization to ACS');
    }
    return (response.data.policy_sets || []).length > 0 ? response.data.policy_sets[0] : {};
  }
}

/**
 * General authorizer. Marshalls data and requests access to the Access Control Service (ACS).
 */
export class ACSAuthZ implements IAuthZ {
  acs: any;
  /**
   *
   * @param acs Access Control Service definition (gRPC)
   */
  constructor(acs: any) {
    this.acs = acs;
  }

  /**
   * Perform request to access-control-srv
   * @param subject
   * @param action
   * @param resource
   */
  async isAllowed(request: Request<AuthZTarget, AuthZContext>, hierarchicalScope?: any): Promise<Response> {
    const authZRequest = this.prepareRequest(request);
    authZRequest.context = {
      subject: {},
      resources: [],
      security: this.encode(request.context.security)
    };
    let resources = request.target.resources;

    const subject = request.target.subject;
    if (subject && subject.unauthenticated) {
      // New user registering
      subject.role_associations = [];
    }

    // TODO disabling the heirarchical scop check as this would need graph-srv
    // exposed from resource-srv
    if (request.target.action != 'execute') {
      if (!hierarchicalScope) {
        hierarchicalScope = await this.createHierarchicalScopeTrees(subject.role_associations);
      }
      authZRequest.context.subject = this.encode(_.merge(subject, {
        hierarchical_scope: hierarchicalScope
      }));
      // let idResource = [{ id: subject.id }];
      if (request.target.action == 'create' || request.target.action == 'modify'
        || request.target.action == 'delete') {
        // insert temporary IDs into resources which are yet to be created
        let counter = 0;
        resources = _.cloneDeep(request.target.resources).map((resource) => {
          if (!resource.instance.id) {
            resource.instance.id = String(counter++);
            resource.fields.push('id');
          }
          return resource;
        });
      }
      authZRequest.context.resources = this.encode(resources);
    }

    const response = await this.acs.isAllowed(authZRequest);

    if (_.isEmpty(response) || _.isEmpty(response.data)) {
      console.log(response.error);
      logger.error('Unexpected empty response from ACS');
    } else if (response.data.decision) {
      return {
        decision: response.data.decision as Decision
      };
    }

    if (response.error) {
      logger.verbose('Error while requesting authorization to ACS...', { error: response.error.message });
      throw new Error('Error while requesting authorization to ACS');
    }

    return {
      decision: Decision.DENY
    };
  }

  /**
  * Perform request to access-control-srv
  * @param subject
  * @param action
  * @param resource
  */
  async whatIsAllowed(request: Request<AuthZWhatIsAllowedTarget, AuthZContext>): Promise<PolicySetRQ> {
    const authZRequest = this.prepareRequest(request);
    authZRequest.context = {};

    const response = await this.acs.whatIsAllowed(authZRequest);
    if (_.isEmpty(response) || _.isEmpty(response.data)) {
      logger.error('Unexpected empty response from ACS');
    }

    if (response.error) {
      logger.verbose('Error while requesting authorization to ACS...', { error: response.error.message });
      throw new Error('Error while requesting authorization to ACS');
    }
    return (response.data.policy_sets || []).length > 0 ? response.data.policy_sets[0] : {};
  }

  private encode(object: any): any {
    if (_.isArray(object)) {
      return _.map(object, this.encode.bind(this));
    } else {
      return {
        value: Buffer.from(JSON.stringify(object))
      };
    }
  }

  private async createHierarchicalScopeTrees(roleAssociations: RoleAssociation[]): Promise<HierarchicalScope[]> {
    const ids = new Set<string>();
    for (let roleAssoc of roleAssociations) {
      const attributes = roleAssoc.attributes || [];
      for (let attribute of attributes) {
        if (attribute.id == urns.roleScopingInstance) {
          ids.add(attribute.value);
        }
      }
    }
    if (ids.size == 0) { // subject has no hierarchical scope; e.g: SuperAdmin
      return [];
    }
    const hierarchicalScope: HierarchicalScope[] = [];
    const setArray = [...ids];
    for (let id of setArray) {
      hierarchicalScope.push({ id });
    }
    return hierarchicalScope;
  }

  reduceUserScope(user: UserSessionData): UserSessionData {
    const mainScopes = user.scope ? user.scope.role_associations : [];
    const orgScope = user.scope ? user.scope.scopeOrganization : user.default_scope;

    if (!orgScope || _.isEmpty(mainScopes)) {
      return; // user has no scope
    }
    user.role_associations = mainScopes;
    return user;
  }

  prepareRequest(request: Request<AuthZTarget | AuthZWhatIsAllowedTarget, AuthZContext>): any {
    let { subject, resources, action } = request.target;
    this.reduceUserScope(subject);

    const authZRequest: any = {
      target: {
        action: createActionTarget(action),
        subject: createSubjectTarget(subject),
      },
    };
    if (_.isArray(action)) {
      // whatIsAllowed
      authZRequest.target.resources = createResourceTargetWhatIsAllowed(resources);
    } else {
      // isAllowed
      if (request.target.action == 'create' || request.target.action == 'modify'
        || request.target.action == 'delete') {
        // insert temporary IDs into resources which are yet to be created
        let counter = 0;
        resources = _.cloneDeep(request.target.resources).map((resource) => {
          if (!resource.instance.id) {
            resource.instance.id = String(counter++);
            resource.fields.push('id');
          }
          return resource;
        });
      }

      authZRequest.target.resources = createResourceTarget(resources, action);
    }

    return authZRequest;
  }
}

export async function initAuthZ(): Promise<void> {
  if (!authZ) {
    const authzCfg = cfg.get('authorization');
    // gRPC interface for access-control-srv
    if (authzCfg.enabled) {
      const grpcConfig = cfg.get('client:acs-srv');
      const client = new Client(grpcConfig, logger);
      const acs = await client.connect();
      authZ = new ACSAuthZ(acs);
    }
  }
}

export function createActionTarget(action: AuthZAction | AuthZAction[]): Attribute[] {
  if (_.isArray(action)) {
    let actionList = [];
    for (let eachAction of action) {
      actionList.push({
        id: urns.actionID,
        value: urns.action + `:${eachAction}`
      });
    }
    return actionList;
  }
  else {
    return [{
      id: urns.actionID,
      value: urns.action + `:${action}`
    }];
  }
}

export function createSubjectTarget(subject: UserSessionData | UnauthenticatedData): Attribute[] {
  if (subject.unauthenticated) {
    return [{
      id: urns.unauthenticated_user,
      value: 'true'
    }];
  }
  subject = subject as UserSessionData;
  let flattened = [
    {
      id: urns.resourceID,
      value: subject.id
    }];

  subject.role_associations.forEach((roleAssoc) => {
    flattened.push({
      id: urns.role,
      value: roleAssoc.role
    });

    flattened = flattened.concat(roleAssoc.attributes);
  });
  return flattened;
}

export function createResourceTarget(resources: Resource[], action: AuthZAction | AuthZAction[]) {
  const flattened: Attribute[] = [];
  resources.forEach((resource) => {
    if (action != 'execute') {
      const resourceType = formatResourceType(resource.type);

      if (resourceType) {
        flattened.push({
          id: urns.entity,
          value: urns.model + `:${resourceType}`
        });
      }
      if (resource.instance && resource.instance.id) {
        flattened.push({
          id: urns.resourceID,
          value: resource.instance.id
        });
      }

      if (resource.fields) {
        resource.fields.forEach((field) => {
          flattened.push({
            id: urns.property,
            value: urns.model + `:${resourceType}#${field}`
          });
        });
      }
    } else {
      resources.forEach((resource) => {
        flattened.push({
          id: urns.operation,
          value: resource.type
        });
      });
    }
  });

  return flattened;
}

export function createResourceTargetWhatIsAllowed(resources: Resource[]) {
  const flattened: Attribute[] = [];
  resources.forEach((resource) => {
    const resourceType = formatResourceType(resource.type);

    if (resource.type.startsWith('mutation') || resource.type.startsWith('query')) {
      resources.forEach((resource) => {
        flattened.push({
          id: urns.operation,
          value: resource.type
        });
      });
    }
    else {
      flattened.push({
        id: urns.entity,
        value: urns.model + `:${resourceType}`
      });
    }
  });

  return flattened;
}

function formatResourceType(type: string): string {
  // e.g: contact_point -> contact_point.ContactPoint
  const prefix = type;
  const suffixArray = type.split('_').map((word) => {
    return word.charAt(0).toUpperCase() + word.substring(1);
  });
  const suffix = suffixArray.join('');
  return `${prefix}.${suffix}`;
}
