import * as _ from 'lodash';
import {
  AuthZContext, Attribute,
  AuthZAction, AuthZTarget, UserSessionData,
  AuthZWhatIsAllowedTarget, PolicySetRQ, IAuthZ,
  NoAuthTarget, UnauthenticatedData, NoAuthWhatIsAllowedTarget, RoleAssociation,
  HierarchicalScope, Request, Resource, Decision
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

  async isAllowed(request: Request<NoAuthTarget, AuthZContext>): Promise<Decision> {
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
      return response.data.decision;
    }

    if (response.error) {
      logger.verbose('Error while requesting authorization to ACS...', { error: response.error.message });
      throw new Error('Error while requesting authorization to ACS');
    }

    return Decision.DENY;

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
  async isAllowed(request: Request<AuthZTarget, AuthZContext>, hierarchicalScope?: any): Promise<Decision> {
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


    if (!hierarchicalScope) {
      hierarchicalScope = await this.createHierarchicalScopeTrees(subject.role_associations);
    }
    authZRequest.context.subject = this.encode(_.merge(subject, {
      hierarchical_scope: hierarchicalScope
    }));
    // let idResource = [{ id: subject.id }];
    if (request.target.action == 'CREATE' || request.target.action == 'MODIFY'
      || request.target.action == 'DELETE') {
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

    const response = await this.acs.isAllowed(authZRequest);

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

  prepareRequest(request: Request<AuthZTarget | AuthZWhatIsAllowedTarget, AuthZContext>): any {
    let { subject, resources, action } = request.target;
    // this.reduceUserScope(subject);

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
      if (request.target.action == 'CREATE' || request.target.action == 'MODIFY'
        || request.target.action == 'DELETE') {
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

export function createActionTarget(action: any): Attribute[] {
  if (_.isArray(action)) {
    let actionList = [];
    for (let eachAction of action) {
      eachAction = eachAction.valueOf().toLowerCase();
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
      value: urns.action + `:${action.valueOf().toLowerCase()}`
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
      id: urns.subjectID,
      value: subject.id
    }];

  if (subject.scope) {
    let attributes = [
      {
        id: urns.roleScopingEntity,
        value: urns.orgScope
      },
      {
        id: urns.roleScopingInstance,
        value: subject.scope
      }
    ];
    flattened = flattened.concat(attributes);
  }
  return flattened;
}

export function createResourceTarget(resources: Resource[], action: AuthZAction | AuthZAction[]) {
  const flattened: Attribute[] = [];
  resources.forEach((resource) => {
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
