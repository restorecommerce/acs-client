import {
  RoleAssociation, UserScope, UserSessionData,
  PolicySetRQ, Effect, AttributeTarget, Attribute
} from './acs/interfaces';
import * as _ from 'lodash';
import { QueryArguments, UserQueryArguments } from './acs/resolver';
import { errors, cfg } from './config';
import * as nodeEval from 'node-eval';
import logger from './logger';

export async function reduceRoleAssociations(roleAssociations: RoleAssociation[],
  scopeID: string): Promise<UserScope> {
  const urns = cfg.get('authorization:urns');
  const scope = {
    role_associations: [],
    scopeOrganization: scopeID
  };

  for (let association of roleAssociations) {
    if (!_.isEmpty(association.attributes)) {
      const foundAttributes: Attribute[] = [];
      for (let i = 0; i < association.attributes.length; i += 2) {
        const attribute = association.attributes[i];
        if (attribute.id == urns.roleScopingEntity &&
          attribute.value == urns.organization) {
          const next = association.attributes[i + 1];
          let inScope = false;
          if (next.id == urns.roleScopingInstance) {
            inScope = next.value == scopeID;
          }

          if (inScope) {
            foundAttributes.push(attribute);
            foundAttributes.push(next);
          }
        }
      }
      if (!_.isEmpty(foundAttributes)) {
        scope.role_associations.push({
          role: association.role,
          attributes: foundAttributes
        });
      }
    }
  }

  return scope;
}

export async function convertDBUser(user: UserSessionData): Promise<UserSessionData> {
  const defaultScope: string = user.default_scope || undefined;
  let scope: UserScope;
  if (defaultScope) {
    scope = await reduceRoleAssociations(user.role_associations, defaultScope);
  }

  return _.merge(_.pick(user, [
    'id', 'name', 'email', 'locale_id', 'timezone_id', 'role_associations', 'first_name', 'last_name', 'default_scope'
  ]), {
    scope
  });
}

export function handleError(err: string | Error | any): any {
  let error;
  if (typeof err == 'string') {
    error = errors[err] || errors.SYSTEM_ERROR;
  } else {
    error = errors.SYSTEM_ERROR;
  }
  return error;
}

export async function buildFilterPermissions(policySet: PolicySetRQ,
  ctx: any, database?: string): Promise<QueryArguments | UserQueryArguments> {
  const user = ctx.session.data as UserSessionData;
  const scope = user.default_scope;
  let userScopes: string[] = [];
  if (ctx.session.data && ctx.session.data.userScopes && ctx.session.data.userScopes.length > 0) {
    userScopes = ctx.session.data.userScopes;
  } else {
    userScopes = [scope];
  }

  const urns = cfg.get('authorization:urns');
  let query = {
    filter: []
  };

  const pSetAlgorithm = policySet.combining_algorithm;
  const policyEffects = [];
  const policyFilters = [];

  if (policySet.policies) {
    for (let policy of policySet.policies) {
      if (policy.has_rules) {
        const algorithm = policy.combining_algorithm;
        // check pSet.CA, target attributes and effect
        // if not effect, check rule and do the same there!
        let effect: Effect;
        for (let rule of policy.rules) {
          if (algorithm == urns.permitOverrides && rule.effect == Effect.PERMIT) {
            effect = Effect.PERMIT;
            break;
          } else if (algorithm == urns.denyOverrides && rule.effect == Effect.DENY) {
            effect = Effect.DENY;
          }
        }

        if (!effect) {
          effect = algorithm == urns.permitOverrides ? Effect.DENY : Effect.PERMIT;
        }

        for (let rule of policy.rules) {
          if (rule.effect == effect) {
            policyFilters.push(buildQueryFromTarget(rule.target, effect, userScopes, urns, rule.condition, ctx, database));
          }
        }
        policyEffects.push(effect);
      } else {
        policyEffects.push(policy.effect);
      }
    }
  }

  if (_.isEmpty(policyEffects)) {
    return null;
  }

  let applicable: Effect;
  if (pSetAlgorithm == urns.permitOverrides) {
    applicable = _.includes(policyEffects, Effect.PERMIT) ? Effect.PERMIT : Effect.DENY;
  } else {
    applicable = _.includes(policyEffects, Effect.DENY) ? Effect.DENY : Effect.PERMIT;
  }

  const key = applicable == Effect.PERMIT ? '$or' : '$and';
  for (let policy of policyFilters) {
    if (policy.filter && database && database === 'postgres') {
      // add a filter for org key based on user scope
      let keys = Object.keys(policy.filter);
      query['filter'] = [];
      for (let key of keys) {
        query['filter'].push(policy.filter[key]);
      }
      continue;
    }

    if (policy.filter) {
      (query as any) = { filter: {} };
      if (!query.filter[key]) {
        query.filter[key] = [];
      }
      query.filter[key].push(policy.filter);
    }
    if (policy.scope && applicable == Effect.PERMIT && !query['custom_query']) {
      if (!query['custom_queries']) {
        query['custom_queries'] = [];
      }

      if (!_.includes(query['custom_queries'], policy.scope.custom_query)) {
        query['custom_queries'].push(policy.scope.custom_query);

        if (!query['custom_arguments']) {
          query['custom_arguments'] = {};
        }
        _.merge(query['custom_arguments'], policy.scope.custom_arguments);
      }
    }
    if (policy.field) {
      if (!query['field']) {
        query['field'] = policy.field;
      } else {
        query['field'] = policy.field.concat(query['field']);
      }
    }
  }

  if (!_.isEmpty(query) && (!_.isNil(query.filter) || !_.isEmpty(query['field']) || !_.isEmpty(query['custom_query']))) {
    if (query['custom_arguments']) {
      query['custom_arguments'] = { value: Buffer.from(JSON.stringify(query['custom_arguments'])) };
    }
    return query;
  }
  return undefined;
}

interface QueryParams {
  scope?: any;
  filter?: any;
  field?: any[];
}

function buildQueryFromTarget(target: AttributeTarget, effect: Effect,
  userTotalScope: string[], urns: any, condition?: string, context?: any, database?: string): QueryParams {
  const { subject, resources } = target;

  const filter = [];
  const query = {};
  let filterId;

  // if there is a condition add this to filter
  if (condition && !_.isEmpty(condition)) {
    condition = condition.replace(/\\n/g, '\n');
    const request = { target, context };
    try {
      filterId = validateCondition(condition, request);
      if (filterId) {
        filter.push({
          id: {
            $eq: filterId
          }
        });
      }
    } catch (err) {
      logger.info('Error caught evaluating condition:', { condition, err });
    }
  }
  const scopingAttribute = _.find(subject, (attribute: Attribute) =>
    attribute.id == urns.roleScopingEntity);
  if (!!scopingAttribute && effect == Effect.PERMIT && !database) { // note: there is currently no query to exclude scopes
    query['scope'] = {
      custom_query: 'filterByOwnership',
      custom_arguments: {
        // value: Buffer.from(JSON.stringify({
        entity: scopingAttribute.value,
        instance: userTotalScope
      }
    };
  } else if (database && database === 'postgres') {
    query['filter'] = [];
    for (let eachScope of userTotalScope) {
      query['filter'].push({ field: 'orgKey', operation: 'eq', value: eachScope });
    }
  }

  for (let attribute of resources) {
    if (attribute.id == urns.resourceID) {
      if (effect == Effect.PERMIT) {
        filter.push({
          id: {
            $eq: attribute.value
          }
        });
      } else {
        filter.push({
          id: {
            $not: {
              $eq: attribute.value
            }
          }
        });
      }
      // add ID filter
    } else if (attribute.id == urns.property) {
      // add fields filter
      if (!query['field']) {
        query['field'] = [];
      }
      query['field'].push({
        name: attribute.value.split('#')[1],
        include: effect == Effect.PERMIT
      });
    }
  }

  const key = effect == Effect.PERMIT ? '$or' : '$and';
  if (query['filter']) {
    query['filter'] = Object.assign({}, query['filter'], { [key]: filter });
  } else {
    query['filter'] = {
      [key]: filter
    };
  }
  return query;
}

function validateCondition(condition: string, request: any): boolean {
  return nodeEval(condition, 'condition.js', request);
}