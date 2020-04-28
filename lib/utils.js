"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const interfaces_1 = require("./acs/interfaces");
const _ = require("lodash");
const config_1 = require("./config");
const nodeEval = require("node-eval");
const logger_1 = require("./logger");
exports.reduceRoleAssociations = (roleAssociations, scopeID) => __awaiter(void 0, void 0, void 0, function* () {
    const urns = config_1.cfg.get('authorization:urns');
    const scope = {
        role_associations: [],
        scopeOrganization: scopeID
    };
    for (let association of roleAssociations) {
        if (!_.isEmpty(association.attributes)) {
            const foundAttributes = [];
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
});
exports.handleError = (err) => {
    let error;
    if (typeof err == 'string') {
        error = config_1.errors[err] || config_1.errors.SYSTEM_ERROR;
    }
    else {
        error = config_1.errors.SYSTEM_ERROR;
    }
    return error;
};
const reduceUserScope = (hrScope, reducedUserScope) => {
    reducedUserScope.push(hrScope.id);
    if (hrScope.children) {
        for (let childNode of hrScope.children) {
            reduceUserScope(childNode, reducedUserScope);
        }
    }
};
const checkTargetScopeExists = (hrScope, targetScope, reducedUserScope) => {
    if (hrScope.id === targetScope) {
        // found the target scope object, iterate and put the orgs in reducedUserScope array
        logger_1.default.debug(`Target entity match found in the user's hierarchical scope`);
        reduceUserScope(hrScope, reducedUserScope);
        return true;
    }
    else if (hrScope.children) {
        for (let childNode of hrScope.children) {
            if (checkTargetScopeExists(childNode, targetScope, reducedUserScope)) {
                return true;
            }
        }
    }
    return false;
};
const checkSubjectMatch = (user, ruleSubjectAttributes, reducedUserScope) => {
    // 1) Iterate through ruleSubjectAttributes and check if the roleScopingEntity URN and
    // role URN exists
    // 2) Now check if the subject rule role value matches with one of the users ctx role_associations
    // then get the corresponding scope instance and check if the targetScope is present in user HR scope Object
    let roleScopeEntExists = false;
    let roleValueExists = false;
    let ruleRoleValue;
    let ruleRoleScopeEntityName;
    const urns = config_1.cfg.get('authorization:urns');
    if (ruleSubjectAttributes.length === 0) {
        return true;
    }
    for (let attribute of ruleSubjectAttributes) {
        if (attribute.id === urns.roleScopingEntity) {
            roleScopeEntExists = true;
            ruleRoleScopeEntityName = attribute.value;
        }
        else if (attribute.id === urns.role) {
            roleValueExists = true;
            ruleRoleValue = attribute.value;
        }
    }
    let userAssocScope;
    let userAssocHRScope;
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
                    }
                    else if (roleScopeEntityNameMatched && roleAttrs.id === urns.roleScopingInstance) {
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
                if (userAssocHRScope && checkTargetScopeExists(userAssocHRScope, user.scope, reducedUserScope)) {
                    return true;
                }
            }
        }
    }
    else if (!roleScopeEntExists && roleValueExists) {
        const userRoleAssocs = user.role_associations;
        for (let role of userRoleAssocs) {
            if (role.role === ruleRoleValue) {
                return true;
            }
        }
    }
    return false;
};
const validateCondition = (condition, request) => {
    return nodeEval(condition, 'condition.js', request);
};
const buildQueryFromTarget = (target, effect, userTotalScope, urns, userCondition, scopingUpdated, condition, reqSubject, database) => {
    const { subject, resources } = target;
    let filter = [];
    const query = {};
    let filterId;
    // if there is a condition add this to filter
    if (condition && !_.isEmpty(condition)) {
        condition = condition.replace(/\\n/g, '\n');
        const request = { target, context: { subject: { id: reqSubject.id } } };
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
        }
        catch (err) {
            logger_1.default.error('Error caught evaluating condition:', { condition, err });
        }
    }
    const scopingAttribute = _.find(subject, (attribute) => attribute.id == urns.roleScopingEntity);
    if (!!scopingAttribute && effect == interfaces_1.Effect.PERMIT && !database) { // note: there is currently no query to exclude scopes
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
    }
    else if (database && database === 'postgres' && effect == interfaces_1.Effect.PERMIT) {
        query['filter'] = [];
        for (let eachScope of userTotalScope) {
            query['filter'].push({ field: 'orgKey', operation: 'eq', value: eachScope });
        }
    }
    for (let attribute of resources) {
        if (attribute.id == urns.resourceID) {
            if (effect == interfaces_1.Effect.PERMIT) {
                filter.push({
                    id: {
                        $eq: attribute.value
                    }
                });
            }
            else {
                filter.push({
                    id: {
                        $not: {
                            $eq: attribute.value
                        }
                    }
                });
            }
            // add ID filter
        }
        else if (attribute.id == urns.property) {
            // add fields filter
            if (!query['field']) {
                query['field'] = [];
            }
            query['field'].push({
                name: attribute.value.split('#')[1],
                include: effect == interfaces_1.Effect.PERMIT
            });
        }
    }
    const key = effect == interfaces_1.Effect.PERMIT ? '$or' : '$and';
    if (query['filter']) {
        query['filter'] = Object.assign({}, query['filter'], { [key]: filter });
    }
    else if (!_.isEmpty(filter) || key == '$or') {
        query['filter'] = {
            [key]: filter
        };
    }
    query.scopingUpdated = scopingUpdated;
    query.userCondition = userCondition;
    return query;
};
exports.buildFilterPermissions = (policySet, subject, database) => {
    const urns = config_1.cfg.get('authorization:urns');
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
                        logger_1.default.debug(`Skipping policy as policy subject and user subject don't match`);
                        continue;
                    }
                }
                let effect;
                for (let rule of policy.rules) {
                    if (algorithm == urns.permitOverrides && rule.effect == interfaces_1.Effect.PERMIT) {
                        effect = interfaces_1.Effect.PERMIT;
                        break;
                    }
                    else if (algorithm == urns.denyOverrides && rule.effect == interfaces_1.Effect.DENY) {
                        effect = interfaces_1.Effect.DENY;
                    }
                }
                if (!effect) {
                    effect = algorithm == urns.permitOverrides ? interfaces_1.Effect.DENY : interfaces_1.Effect.PERMIT;
                }
                let userCondition = false;
                let scopingUpdated = false;
                for (let rule of policy.rules) {
                    let reducedUserScope = [];
                    if (rule.target && rule.target.subject) {
                        let userSubjectMatched = checkSubjectMatch(subject, rule.target.subject, reducedUserScope);
                        if (!userSubjectMatched) {
                            logger_1.default.debug(`Skipping rule as user subject and rule subject don't match`);
                            continue;
                        }
                        else if (userSubjectMatched && reducedUserScope.length === 0) {
                            reducedUserScope = [subject.scope];
                        }
                    }
                    if (rule.effect == effect) {
                        const filterPermissions = buildQueryFromTarget(rule.target, effect, reducedUserScope, urns, userCondition, scopingUpdated, rule.condition, subject, database);
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
            }
            else {
                policyEffects.push(policy.effect);
            }
        }
    }
    if (_.isEmpty(policyEffects)) {
        return null;
    }
    let applicable;
    if (pSetAlgorithm == urns.permitOverrides) {
        applicable = _.includes(policyEffects, interfaces_1.Effect.PERMIT) ? interfaces_1.Effect.PERMIT : interfaces_1.Effect.DENY;
    }
    else {
        applicable = _.includes(policyEffects, interfaces_1.Effect.DENY) ? interfaces_1.Effect.DENY : interfaces_1.Effect.PERMIT;
    }
    const key = applicable == interfaces_1.Effect.PERMIT ? '$or' : '$and';
    if (policyFilters.length === 0) {
        return undefined;
    }
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
        if (policy.filter && policy.filter[key] && policy.filter[key].length > 0) {
            query = { filter: {} };
            if (!query.filter[key]) {
                query.filter[key] = [];
            }
            query.filter[key].push(policy.filter);
        }
        if (policy.scope && applicable == interfaces_1.Effect.PERMIT && !query['custom_query']) {
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
            }
            else {
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
const decodeValue = (value) => {
    let ret = {};
    if (value.number_value) {
        ret = value.number_value;
    }
    else if (value.string_value) {
        ret = value.string_value;
    }
    else if (value.list_value) {
        ret = _.map(value.list_value.values, (v) => {
            return exports.toObject(v, true); // eslint-disable-line
        });
    }
    else if (value.struct_value) {
        ret = exports.toObject(value.struct_value); // eslint-disable-line
    }
    else if (!_.isNil(value.bool_value)) {
        ret = value.bool_value;
    }
    return ret;
};
exports.toObject = (struct, fromArray = false) => {
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
