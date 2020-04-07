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
const _ = require("lodash");
const interfaces_1 = require("./interfaces");
const interfaces_2 = require("./interfaces");
const logger_1 = require("../logger");
const config_1 = require("../config");
const utils_1 = require("../utils");
const grpc_client_1 = require("@restorecommerce/grpc-client");
const authz_1 = require("./authz");
const errors_1 = require("./errors");
const subjectIsUnauthenticated = (subject) => {
    return !!subject
        && 'unauthenticated' in subject && subject['unauthenticated'];
};
const whatIsAllowedRequest = (subject, resources, action, authZ) => __awaiter(void 0, void 0, void 0, function* () {
    if (subjectIsUnauthenticated(subject)) {
        const grpcConfig = config_1.cfg.get('client:acs-srv');
        const acsClient = new grpc_client_1.Client(grpcConfig, logger_1.default);
        const acs = yield acsClient.connect();
        return new authz_1.UnAuthZ(acs).whatIsAllowed({
            target: {
                action, resources, subject: subject
            },
            context: {
                security: {}
            }
        });
    }
    else {
        return authZ.whatIsAllowed({
            context: {
                security: {}
            },
            target: {
                action,
                resources,
                subject: subject
            }
        }, subject.hierarchical_scopes);
    }
});
const isReadRequest = (object) => {
    return 'entity' in object;
};
exports.isAllowedRequest = (subject, resources, action, authZ) => __awaiter(void 0, void 0, void 0, function* () {
    if (subjectIsUnauthenticated(subject)) {
        const grpcConfig = config_1.cfg.get('client:acs-srv');
        const acsClient = new grpc_client_1.Client(grpcConfig, logger_1.default);
        const acs = yield acsClient.connect();
        return new authz_1.UnAuthZ(acs).isAllowed({
            target: {
                action, resources, subject: subject
            },
            context: {
                security: {}
            }
        });
    }
    else {
        return authZ.isAllowed({
            context: {
                security: {}
            },
            target: {
                action,
                resources,
                subject
            }
        }, subject.hierarchical_scopes);
    }
});
const createMetadata = (resource, userData) => {
    let ownerAttributes = [];
    if (resource.meta && resource.meta.owner) {
        ownerAttributes = _.cloneDeep(resource.meta.owner);
    }
    else if (resource.owner) {
        ownerAttributes = _.cloneDeep(resource.owner);
    }
    const urns = config_1.cfg.get('authorization:urns');
    let ownUser = false;
    let foundEntity = false;
    for (let attribute of ownerAttributes) {
        if (attribute.id == urns.ownerIndicatoryEntity && attribute.value == urns.user) {
            foundEntity = true;
        }
        else if (attribute.id == urns.ownerInstance && attribute.value == userData.id && foundEntity) {
            ownUser = true;
            break;
        }
    }
    if (resource.orgKey) {
        ownerAttributes.push({
            id: urns.ownerIndicatoryEntity,
            value: urns.organization
        }, {
            id: urns.ownerInstance,
            value: resource.orgKey
        });
    }
    if (!ownUser && !!userData.id) {
        ownerAttributes.push({
            id: urns.ownerIndicatoryEntity,
            value: urns.user
        }, {
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
const convertToObject = (resources) => {
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
 * @param {Subject | ApiKey} subject Contains subject information or ApiKey
 * @param {Resource | Resource[] | ReadRequest} request request object either Resource or ReadRequest
 * @param {AuthZAction} action Action to be performed on resource
 * @param {ACSAuthZ} authZ ACS Authorization Object containing grpc client connection for `access-control-srv`
 * @returns {Decision | PolicySetRQ}
 */
exports.accessRequest = (subject, request, action, authZ) => __awaiter(void 0, void 0, void 0, function* () {
    // TODO: add command to sync dynamic apikey
    let reqApiKey = subject.api_key;
    // if apiKey mode is enabled
    if (reqApiKey) {
        let configuredApiKey = config_1.cfg.get('authentication:apiKey');
        if (configuredApiKey && configuredApiKey === reqApiKey) {
            if (action === interfaces_2.AuthZAction.CREATE || action === interfaces_2.AuthZAction.MODIFY ||
                action === interfaces_2.AuthZAction.DELETE || action === interfaces_2.AuthZAction.EXECUTE) {
                return interfaces_1.Decision.PERMIT;
            }
            else if (action === interfaces_2.AuthZAction.READ) {
                if (!subject) {
                    subject = { unauthenticated: true };
                }
                return yield whatIsAllowedRequest(subject, [{
                        type: request.entity,
                        namespace: request.namespace
                    }], [action], authZ);
            }
        }
    }
    let authzEnabled = config_1.cfg.get('authorization:enabled');
    let authzEnforced = config_1.cfg.get('authorization:enforce');
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
        if (action === interfaces_2.AuthZAction.CREATE || action === interfaces_2.AuthZAction.MODIFY ||
            action === interfaces_2.AuthZAction.DELETE || action === interfaces_2.AuthZAction.EXECUTE) {
            return interfaces_1.Decision.PERMIT;
        }
        else if (action === interfaces_2.AuthZAction.READ) {
            // make auth ctx uanth since authorization is disabled
            if (!subject) {
                subject = { unauthenticated: true };
            }
            return yield whatIsAllowedRequest(subject, [{
                    type: request.entity,
                    namespace: request.namespace
                }], [action], authZ);
        }
    }
    if (!subject) {
        throw new errors_1.Unauthenticated(config_1.errors.USER_NOT_LOGGED_IN.message, config_1.errors.USER_NOT_LOGGED_IN.code);
    }
    let resources = [];
    let requestingUserName_ID = subject.id;
    let targetScope = subject.scope;
    // for read operations
    if (action == interfaces_2.AuthZAction.READ && isReadRequest(request)
        // for action create or modify with read request to get policySetRQ
        || ((action == interfaces_2.AuthZAction.CREATE || action == interfaces_2.AuthZAction.MODIFY) && isReadRequest(request))) {
        const resourceName = request.entity;
        let policySet;
        try {
            // retrieving set of applicable policies/rules from ACS
            // Note: it is assumed that there is only one policy set
            policySet = yield whatIsAllowedRequest(subject, [{
                    type: resourceName,
                    namespace: request.namespace
                }], [action], authZ);
        }
        catch (err) {
            logger_1.default.error('Error calling whatIsAllowed:', { message: err.message });
            throw err;
        }
        // handle case if policySet is empty
        if (_.isEmpty(policySet) && authzEnforced) {
            const msg = `Access not allowed for request with subject:${requestingUserName_ID}, ` +
                `resource:${resourceName}, action:${action}, target_scope:${targetScope}; the response was INDETERMINATE`;
            const details = 'no matching policy/rule could be found';
            logger_1.default.verbose(msg);
            logger_1.default.verbose('Details:', { details });
            throw new errors_1.PermissionDenied(msg, config_1.errors.ACTION_NOT_ALLOWED.code);
        }
        if (_.isEmpty(policySet) && !authzEnforced) {
            logger_1.default.verbose(`The Access response was INDETERMIATE for a request with subject:` +
                `${requestingUserName_ID}, resource:${resourceName}, action:${action}, target_scope:${targetScope} ` +
                `as no matching policy/rule could be found, but since ACS enforcement ` +
                `config is disabled overriding the ACS result`);
        }
        // extend input filter to enforce applicable policies
        const permissionArguments = utils_1.buildFilterPermissions(policySet, subject, request.database);
        if (!permissionArguments && authzEnforced) {
            const msg = `Access not allowed for request with subject:${requestingUserName_ID}, ` +
                `resource:${resourceName}, action:${action}, target_scope:${targetScope}; the response was DENY`;
            const details = `Subject:${requestingUserName_ID} does not have access to target scope ${targetScope}}`;
            logger_1.default.verbose(msg);
            logger_1.default.verbose('Details:', { details });
            throw new errors_1.PermissionDenied(msg, config_1.errors.ACTION_NOT_ALLOWED.code);
        }
        if (!permissionArguments && !authzEnforced) {
            logger_1.default.verbose(`The Access response was DENY for a request from subject:${requestingUserName_ID}, ` +
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
    }
    else {
        resources = request;
    }
    // default deny
    let decision = interfaces_1.Decision.DENY;
    // for write operations
    if (!_.isEmpty(resources) || action == interfaces_2.AuthZAction.DELETE || action == interfaces_2.AuthZAction.EXECUTE) {
        // authorization
        decision = yield exports.isAllowedRequest(subject, resources, action, authZ);
        if (decision && decision != interfaces_1.Decision.PERMIT && authzEnforced) {
            let details = '';
            if (decision === interfaces_1.Decision.INDETERMINATE) {
                details = 'No matching policy / rule was found';
            }
            else if (decision === interfaces_1.Decision.DENY) {
                details = `Subject:${requestingUserName_ID} does not have access to requested target scope ${targetScope}`;
            }
            const msg = `Access not allowed for request with subject:${requestingUserName_ID}, ` +
                `resource:${resources[0].type}, action:${action}, target_scope:${targetScope}; the response was ${decision}`;
            logger_1.default.verbose(msg);
            logger_1.default.verbose('Details:', { details });
            throw new errors_1.PermissionDenied(msg, config_1.errors.ACTION_NOT_ALLOWED.code);
        }
    }
    if (!authzEnforced && decision && decision != interfaces_1.Decision.PERMIT) {
        let details = '';
        if (decision === interfaces_1.Decision.INDETERMINATE) {
            details = 'No matching policy / rule was found';
        }
        else if (decision === interfaces_1.Decision.DENY) {
            details = `Subject:${requestingUserName_ID} does not have access to requested target scope ${targetScope}`;
        }
        logger_1.default.verbose(`Access not allowed for request with subject:${requestingUserName_ID}, ` +
            `resource:${resources[0].type}, action:${action}, target_scope:${targetScope}; the response was ${decision}`);
        logger_1.default.verbose(`${details}, Overriding the ACS result as ACS enforce config is disabled`);
        decision = interfaces_1.Decision.PERMIT;
    }
    return decision;
});
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
exports.parseResourceList = (subject, resourceList, action, entity, resourceNamespace, fields) => {
    return resourceList.map((resource) => {
        let instance = convertToObject(resource);
        if (action == interfaces_2.AuthZAction.CREATE || action == interfaces_2.AuthZAction.MODIFY || action == interfaces_2.AuthZAction.DELETE) {
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
exports.isAllowed = (request, authZ) => __awaiter(void 0, void 0, void 0, function* () {
    const response = yield authZ.acs.isAllowed(request);
    if (_.isEmpty(response) || _.isEmpty(response.data)) {
        console.log(response.error);
        logger_1.default.error('Unexpected empty response from ACS');
    }
    else if (response.data.decision) {
        return response.data.decision;
    }
    if (response.error) {
        logger_1.default.verbose('Error while requesting authorization to ACS...', { error: response.error.message });
        throw new Error('Error while requesting authorization to ACS');
    }
    return interfaces_1.Decision.DENY;
});
/**
 * Exposes the whatIsAllowed() api of `access-control-srv` and retruns the response
 * a policy set reverse query `PolicySetRQ`
 * @param {ACSRequest} authZRequest input authorization request
 * @param {ACSContext} ctx Context Object containing requester's subject information
 * @return {PolicySetRQ} set of applicalbe policies and rules for the input request
 */
exports.whatIsAllowed = (request, authZ) => __awaiter(void 0, void 0, void 0, function* () {
    const response = yield authZ.acs.whatIsAllowed(request);
    if (_.isEmpty(response) || _.isEmpty(response.data)) {
        logger_1.default.error('Unexpected empty response from ACS');
    }
    if (response.error) {
        logger_1.default.verbose('Error while requesting authorization to ACS...', { error: response.error.message });
        throw new Error('Error while requesting authorization to ACS');
    }
    return (response.data.policy_sets || []).length > 0 ? response.data.policy_sets[0] : {};
});
