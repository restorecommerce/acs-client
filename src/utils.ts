import {
  RoleAssociation, UserScope, Subject,
  PolicySetRQ, Effect, AttributeTarget, Attribute, HierarchicalScope
} from './acs/interfaces';
import * as _ from 'lodash';
import { QueryArguments, UserQueryArguments } from './acs/resolver';
import { errors, cfg } from './config';
import * as nodeEval from 'node-eval';
import logger from './logger';
import { get } from './acs/cache';
import { createClient } from 'redis';

export const reduceRoleAssociations = async (roleAssociations: RoleAssociation[],
  scopeID: string): Promise<UserScope> => {
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
};

export const handleError = (err: string | Error | any): any => {
  let error;
  if (typeof err == 'string') {
    error = errors[err] || errors.SYSTEM_ERROR;
  } else {
    error = errors.SYSTEM_ERROR;
  }
  return error;
};

const reduceUserScope = (hrScope: HierarchicalScope, reducedUserScope: string[],
  hierarchicalRoleScoping: string) => {
  reducedUserScope.push(hrScope.id);
  if (hrScope.children && hierarchicalRoleScoping === 'true') {
    for (let childNode of hrScope.children) {
      reduceUserScope(childNode, reducedUserScope, hierarchicalRoleScoping);
    }
  }
};

const checkTargetScopeExists = (hrScope: HierarchicalScope, targetScope: string,
  reducedUserScope: string[], hierarchicalRoleScopingCheck: string): boolean => {
  if (hrScope.id === targetScope) {
    // found the target scope object, iterate and put the orgs in reducedUserScope array
    logger.debug(`Target entity match found in the user's hierarchical scope`);
    reduceUserScope(hrScope, reducedUserScope, hierarchicalRoleScopingCheck);
    return true;
  } else if (hrScope.children && hierarchicalRoleScopingCheck === 'true') {
    for (let childNode of hrScope.children) {
      if (checkTargetScopeExists(childNode, targetScope, reducedUserScope, hierarchicalRoleScopingCheck)) {
        return true;
      }
    }
  }
  return false;
};

const checkSubjectMatch = (user: Subject, ruleSubjectAttributes: Attribute[],
  reducedUserScope?: string[]): boolean => {
  // 1) Iterate through ruleSubjectAttributes and check if the roleScopingEntity URN and
  // role URN exists
  // 2) Now check if the subject rule role value matches with one of the users ctx role_associations
  // then get the corresponding scope instance and check if the targetScope is present in user HR scope Object

  let roleScopeEntExists = false;
  let roleValueExists = false;
  // by default HR scoping check is considered
  let hierarchicalRoleScopingCheck = 'true';
  let ruleRoleValue;
  let ruleRoleScopeEntityName;
  const urns = cfg.get('authorization:urns');
  if (ruleSubjectAttributes.length === 0) {
    return true;
  }
  for (let attribute of ruleSubjectAttributes) {
    if (attribute.id === urns.roleScopingEntity) {
      roleScopeEntExists = true;
      ruleRoleScopeEntityName = attribute.value;
    } else if (attribute.id === urns.role) {
      roleValueExists = true;
      ruleRoleValue = attribute.value;
    } else if (attribute.id === urns.hierarchicalRoleScoping) {
      hierarchicalRoleScopingCheck = attribute.value;
    }
  }

  let userAssocScope;
  let userAssocHRScope: HierarchicalScope;
  if (roleScopeEntExists && roleValueExists) {
    const userRoleAssocs = user.role_associations;
    for (let role of userRoleAssocs) {
      if (role.role === ruleRoleValue) {
        // check the targetScope exists in the user HR scope object
        let roleScopeEntityNameMatched = false;
        for (let roleAttrs of role.attributes) {
          // urn:restorecommerce:acs:names:roleScopingInstance
          if (roleAttrs.id === urns.roleScopingEntity &&
            roleAttrs.value === ruleRoleScopeEntityName) {
            roleScopeEntityNameMatched = true;
          } else if (roleScopeEntityNameMatched && roleAttrs.id === urns.roleScopingInstance) {
            userAssocScope = roleAttrs.value;
            break;
          }
        }
        // check if this userAssocScope's HR object contains the targetScope
        for (let hrScope of user.hierarchical_scopes) {
          if (hrScope.id === userAssocScope) {
            userAssocHRScope = hrScope;
            break;
          }
        }
        // check HR scope matching for subject if hierarchicalRoleScopingCheck is 'true'
        if (userAssocHRScope && checkTargetScopeExists(userAssocHRScope,
          user.scope, reducedUserScope, hierarchicalRoleScopingCheck)) {
          return true;
        }
      }
    }
  } else if (!roleScopeEntExists && roleValueExists) {
    const userRoleAssocs = user.role_associations;
    for (let role of userRoleAssocs) {
      if (role.role === ruleRoleValue) {
        return true;
      }
    }
  }
  return false;
};

const validateCondition = (condition: string, request: any): boolean => {
  return nodeEval(condition, 'condition.js', request);
};

const getRedisKey = async (key: string, redisClient: any): Promise<any> => {
  return new Promise((resolve, reject) => {
    redisClient.get(key, async (err, reply) => {
      if (err) {
        reject(err);
        return;
      }

      if (reply) {
        logger.debug('Found key in cache: ' + key);
        resolve(JSON.parse(reply));
        return;
      }
      if (!err && !reply) {
        logger.info('Key does not exist', { key });
        resolve();
      }
    });
  });
};

export const validateSubjectIdToken = async (subjectID: string, token: string): Promise<any> => {
  const redisConfig = cfg.get('redis');
  redisConfig.db = cfg.get('redis:db-indexes:db-subject') | 1;
  const redisClient = createClient(redisConfig);

  redisConfig.db = cfg.get('redis:db-indexes:db-access-token') | 0;
  const tokenClient = createClient(redisConfig);

  let subjectKey = `cache:${subjectID}:subject`;
  // const subject = await this.getRedisKey(redisKey, this.redisClient);
  const accessTokenKey = `AccessToken:${token}`;
  const idToken = await getRedisKey(accessTokenKey, tokenClient);
  if (!_.isEmpty(idToken) && idToken.claims) {
    const subject = idToken.claims.data;
    if (subject.id === subjectID) {
      logger.debug(`Subject ID ${subjectID} and token match`);
      return true;
    }
  } else if (!idToken) {
    // read subject from db-subject and compare
    const subject = await getRedisKey(subjectKey, redisClient);
    if (subject && !_.isEmpty(subject.tokens)) {
      for (let tokenInfo of subject.tokens) {
        if (tokenInfo.token === token) {
          logger.debug(`Subject ID ${subjectID} and token match`);
          return true;
        }
      }
    } else if (!subject && !idToken) {
      logger.debug('No subject or access token is stored');
      return true;
    }
  }
  logger.debug(`Subject ID ${subjectID} and token don't match`);
  return false;
};


const buildQueryFromTarget = (target: AttributeTarget, effect: Effect,
  userTotalScope: string[], urns: any, userCondition, scopingUpdated,
  condition?: string, reqSubject?: Subject, database?: string): QueryParams => {
  const { subject, resources } = target;

  let filter = [];
  const query: any = {};
  let filterId;

  // if there is a condition add this to filter
  if (condition && !_.isEmpty(condition)) {
    condition = condition.replace(/\\n/g, '\n');
    const request = { target, context: { subject: { id: reqSubject.id, token: reqSubject.token } } };
    try {
      filterId = validateCondition(condition, request);
      // special filter added to filter user read for his own entity
      if (filterId && !scopingUpdated) {
        userCondition = true;
        filter.push({
          id: {
            $eq: filterId
          }
        });
      }
    } catch (err) {
      logger.error('Error caught evaluating condition:', { condition, err });
    }
  }
  const scopingAttribute = _.find(subject, (attribute: Attribute) =>
    attribute.id == urns.roleScopingEntity);
  if (!!scopingAttribute && effect == Effect.PERMIT && !database) { // note: there is currently no query to exclude scopes
    // userTotalScope is an array accumulated scopes for each rule
    if (userCondition) {
      filter = [];
    }
    query['scope'] = {
      custom_query: 'filterByOwnership',
      custom_arguments: {
        // value: Buffer.from(JSON.stringify({
        entity: scopingAttribute.value,
        instance: userTotalScope
      }
    };
    scopingUpdated = true;
  } else if (database && database === 'postgres' && effect == Effect.PERMIT) {
    query['filter'] = [];
    const filterParamKey = cfg.get('authorization:filterParamKey');
    for (let eachScope of userTotalScope) {
      query['filter'].push({ field: filterParamKey, operation: 'eq', value: eachScope });
    }
    // apply filter from condition
    for (let eachFilter of filter) {
      if (eachFilter.id && eachFilter.id.$eq) {
        query['filter'].push({ field: filterParamKey, operation: 'eq', value: eachFilter.id.$eq });
        filter = [];
      }
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
  } else if (!_.isEmpty(filter) || key == '$or') {
    query['filter'] = {
      [key]: filter
    };
  }
  query.scopingUpdated = scopingUpdated;
  query.userCondition = userCondition;
  return query;
};

export const buildFilterPermissions = async (policySet: PolicySetRQ,
  subject: any, database?: string): Promise<QueryArguments | UserQueryArguments> => {
  if (_.isEmpty(subject.role_associations) || _.isEmpty(subject.hierarchical_scopes)) {
    // update subject from redis (restore target scope from subject as it is)
    const targetScope = subject.scope;
    let subjectID = subject.id;
    let token = subject.token;
    const redisSubKey = `cache:${subjectID}:subject`;
    let redisHRScopesKey = `cache:${subjectID}:hrScopes`;
    let redisSub;
    try {
      redisSub = await get(redisSubKey);
      if (redisSub && redisSub.tokens) {
        for (let tokenInfo of redisSub.tokens) {
          if ((tokenInfo.token) === token && tokenInfo.scopes && tokenInfo.scopes.length > 0) {
            redisHRScopesKey = `cache:${subjectID}:${token}:hrScopes`;
          }
        }
      }
    } catch (err) {
      logger.error(err);
    }
    if (redisSub) {
      const hierarchical_scopes = await get(redisHRScopesKey);
      Object.assign(redisSub, { hierarchical_scopes });
      subject = redisSub;
      subject.scope = targetScope;
    }
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
        // iterate through policy_set and check subject in policy and Rule:
        if (policy.target && policy.target.subject) {
          let userSubjectMatched = checkSubjectMatch(subject, policy.target.subject);
          if (!userSubjectMatched) {
            logger.debug(`Skipping policy as policy subject and user subject don't match`);
            continue;
          }
        }
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

        let userCondition = false;
        let scopingUpdated = false;
        for (let rule of policy.rules) {
          let reducedUserScope = [];
          if (rule.target && rule.target.subject) {
            let userSubjectMatched = checkSubjectMatch(subject, rule.target.subject, reducedUserScope);
            if (!userSubjectMatched) {
              logger.debug(`Skipping rule as user subject and rule subject don't match`);
              continue;
            }
          }
          if (rule.effect == effect) {
            const filterPermissions = buildQueryFromTarget(rule.target, effect,
              reducedUserScope, urns, userCondition, scopingUpdated,
              rule.condition, subject, database);
            if (!_.isEmpty(filterPermissions)) {
              scopingUpdated = filterPermissions.scopingUpdated;
              userCondition = filterPermissions.userCondition;
              delete filterPermissions.scopingUpdated;
              delete filterPermissions.userCondition;
            }
            if (!_.isEmpty(filterPermissions)) {
              policyFilters.push(filterPermissions);
            }
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
  if (policyFilters.length === 0) {
    return undefined;
  }
  for (let policy of policyFilters) {
    if (policy.filter && database && database === 'postgres') {
      // add a filter for org key based on user scope
      let keys = Object.keys(policy.filter);
      if (!query['filter']) {
        query['filter'] = [];
      }
      for (let key of keys) {
        query['filter'].push(policy.filter[key]);
      }
      continue;
    }

    if (policy.filter && policy.filter[key] && policy.filter[key].length > 0) {
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
};

interface QueryParams {
  scope?: any;
  filter?: any;
  field?: any[];
  scopingUpdated?: boolean;
  userCondition?: boolean;
}

const decodeValue = (value: any): any => {
  let ret = {};

  if (value.number_value) {
    ret = value.number_value;
  }
  else if (value.string_value) {
    ret = value.string_value;
  }
  else if (value.list_value) {
    ret = _.map(value.list_value.values, (v) => {
      return toObject(v, true); // eslint-disable-line
    });
  }
  else if (value.struct_value) {
    ret = toObject(value.struct_value); // eslint-disable-line
  }
  else if (!_.isNil(value.bool_value)) {
    ret = value.bool_value;
  }
  return ret;
};

export const toObject = (struct: any, fromArray: any = false): Object => {
  let obj = {};
  if (!fromArray) {
    _.forEach(struct.fields, (value, key) => {
      obj[key] = decodeValue(value);
    });
  }
  else {
    obj = decodeValue(struct);
  }
  return obj;
};
