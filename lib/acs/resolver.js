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
const utils_2 = require("./../utils");
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
        });
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
        });
    }
});
/**
 * It turns an API request as can be found in typical Web frameworks like express, koa etc.
 * into a proper ACS request. For write operations it uses `isAllowed()` and for read operations
 * it uses `whatIsAllowed()`. For the latter it extends the filter provided in the `ReadRequst`
 * to enforce the applicapble poilicies. The response is `Decision`
 * or policy set reverse query `PolicySetRQ` depending on the requeste operation `isAllowed()` or
 * `whatIsAllowed()` respectively.
 * @param {Subject | ApiKey} subject Contains subject information or ApiKey
 * @param {any | any[] | ReadRequest} request request object of type any for resource or ReadRequest
 * @param {AuthZAction} action Action to be performed on resource
 * @param {ACSAuthZ} authZ ACS Authorization Object containing grpc client connection for `access-control-srv`
 * @param {string} entity entity name optional
 * @param {string} resourceNameSpace resource name space optional
 * @returns {Decision | PolicySetRQ}
 */
exports.accessRequest = (subject, request, action, authZ, entity, resourceNameSpace) => __awaiter(void 0, void 0, void 0, function* () {
    // TODO: add command to sync dynamic apikey
    let reqApiKey = subject.api_key;
    // if apiKey mode is enabled
    if (reqApiKey) {
        let configuredApiKey = config_1.cfg.get('authentication:apiKey');
        if (configuredApiKey && configuredApiKey === reqApiKey) {
            return interfaces_1.Decision.PERMIT;
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
        return interfaces_1.Decision.PERMIT;
    }
    if (_.isEmpty(subject) || !subject.id) {
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
            throw new errors_1.PermissionDenied(msg, Number(config_1.errors.ACTION_NOT_ALLOWED.code));
        }
        if (_.isEmpty(policySet) && !authzEnforced) {
            logger_1.default.verbose(`The Access response was INDETERMIATE for a request with subject:` +
                `${requestingUserName_ID}, resource:${resourceName}, action:${action}, target_scope:${targetScope} ` +
                `as no matching policy/rule could be found, but since ACS enforcement ` +
                `config is disabled overriding the ACS result`);
        }
        // extend input filter to enforce applicable policies
        let permissionArguments = utils_1.buildFilterPermissions(policySet, subject, request.database);
        if (!permissionArguments && authzEnforced) {
            const msg = `Access not allowed for request with subject:${requestingUserName_ID}, ` +
                `resource:${resourceName}, action:${action}, target_scope:${targetScope}; the response was DENY`;
            const details = `Subject:${requestingUserName_ID} does not have access to target scope ${targetScope}}`;
            logger_1.default.verbose(msg);
            logger_1.default.verbose('Details:', { details });
            throw new errors_1.PermissionDenied(msg, Number(config_1.errors.ACTION_NOT_ALLOWED.code));
        }
        if (!permissionArguments && !authzEnforced) {
            logger_1.default.verbose(`The Access response was DENY for a request from subject:${requestingUserName_ID}, ` +
                `resource:${resourceName}, action:${action}, target_scope:${targetScope}, ` +
                `but since ACS enforcement config is disabled overriding the ACS result`);
        }
        // below fix is to convert the input filter to object only if it is already a structrue
        // i.e. struct filter containing `fileds` property
        if (request.args && request.args.filter && !_.isEmpty(request.args.filter.fields)) {
            if (_.isArray(request.args.filter)) {
                request.args.filter = utils_2.toObject(request.args.filter, true);
            }
            else {
                request.args.filter = utils_2.toObject(request.args.filter);
            }
            if (_.isArray(request.args.filter)) {
                for (let filter of request.args.filter) {
                    if (!_.isArray(permissionArguments.filter)) {
                        permissionArguments.filter = [filter];
                    }
                    permissionArguments.filter.push(filter);
                }
            }
            else {
                if (!_.isArray(permissionArguments.filter)) {
                    permissionArguments.filter = [permissionArguments.filter];
                }
                permissionArguments.filter.push(request.args.filter);
            }
        }
        if (_.isArray(permissionArguments.filter)) {
            permissionArguments.filter = grpc_client_1.toStruct(permissionArguments.filter, true);
        }
        else {
            permissionArguments.filter = grpc_client_1.toStruct(permissionArguments.filter);
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
    let resourceList = [];
    // for write operations
    if (!_.isEmpty(resources) || action === interfaces_2.AuthZAction.DELETE ||
        action === interfaces_2.AuthZAction.EXECUTE || action === interfaces_2.AuthZAction.DROP) {
        // add type and namespace
        for (let resource of resources) {
            resourceList.push({
                fields: _.keys(resource),
                instance: resource,
                type: entity,
                namespace: resourceNameSpace
            });
        }
        // authorization
        try {
            decision = yield exports.isAllowedRequest(subject, resourceList, action, authZ);
        }
        catch (err) {
            throw err;
        }
        if (decision && decision != interfaces_1.Decision.PERMIT && authzEnforced) {
            let details = '';
            if (decision === interfaces_1.Decision.INDETERMINATE) {
                details = 'No matching policy / rule was found';
            }
            else if (decision === interfaces_1.Decision.DENY) {
                details = `Subject:${requestingUserName_ID} does not have access to requested target scope ${targetScope}`;
            }
            const msg = `Access not allowed for request with subject:${requestingUserName_ID}, ` +
                `resource:${resourceList[0].type}, action:${action}, target_scope:${targetScope}; the response was ${decision}`;
            logger_1.default.verbose(msg);
            logger_1.default.verbose('Details:', { details });
            throw new errors_1.PermissionDenied(msg, Number(config_1.errors.ACTION_NOT_ALLOWED.code));
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
            `resource:${resourceList[0].type}, action:${action}, target_scope:${targetScope}; the response was ${decision}`);
        logger_1.default.verbose(`${details}, Overriding the ACS result as ACS enforce config is disabled`);
        decision = interfaces_1.Decision.PERMIT;
    }
    return decision;
});
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
