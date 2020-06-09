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
const grpc_client_1 = require("@restorecommerce/grpc-client");
const config_1 = require("../config");
const logger_1 = require("../logger");
const cache_1 = require("./cache");
const kafka_client_1 = require("@restorecommerce/kafka-client");
const urns = config_1.cfg.get('authorization:urns');
exports.createActionTarget = (action) => {
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
};
exports.createSubjectTarget = (subject) => {
    if (subject.unauthenticated) {
        return [{
                id: urns.unauthenticated_user,
                value: 'true'
            }];
    }
    let flattened = [
        {
            id: urns.subjectID,
            value: subject.id
        }
    ];
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
};
const formatResourceType = (type, namespacePrefix) => {
    // e.g: contact_point -> contact_point.ContactPoint
    const prefix = type;
    const suffixArray = type.split('_').map((word) => {
        return word.charAt(0).toUpperCase() + word.substring(1);
    });
    const suffix = suffixArray.join('');
    if (namespacePrefix) {
        return `${namespacePrefix}.${prefix}.${suffix}`;
    }
    else {
        return `${prefix}.${suffix}`;
    }
};
exports.createResourceTarget = (resources, action) => {
    const flattened = [];
    resources.forEach((resource) => {
        if (action != interfaces_1.AuthZAction.EXECUTE && action != interfaces_1.AuthZAction.DROP) {
            const resourceType = formatResourceType(resource.type, resource.namespace);
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
        }
        else {
            resources.forEach((resource) => {
                flattened.push({
                    id: urns.operation,
                    value: resource.type
                });
            });
        }
    });
    return flattened;
};
exports.createResourceTargetWhatIsAllowed = (resources) => {
    const flattened = [];
    resources.forEach((resource) => {
        const resourceType = formatResourceType(resource.type, resource.namespace);
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
};
class UnAuthZ {
    /**
     *
     * @param acs Access Control Service definition (gRPC)
     */
    constructor(acs) {
        this.acs = acs;
    }
    isAllowed(request) {
        return __awaiter(this, void 0, void 0, function* () {
            const authZRequest = {
                target: {
                    action: exports.createActionTarget(request.target.action),
                    subject: exports.createSubjectTarget(request.target.subject),
                    resources: exports.createResourceTarget(request.target.resources, request.target.action)
                },
                context: request.context
            };
            const response = yield cache_1.getOrFill(authZRequest, (req) => __awaiter(this, void 0, void 0, function* () {
                return this.acs.isAllowed(authZRequest);
            }), 'UnAuthZ:isAllowed');
            if (_.isEmpty(response) || _.isEmpty(response.data)) {
                logger_1.default.error(response.error);
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
    }
    whatIsAllowed(request) {
        return __awaiter(this, void 0, void 0, function* () {
            const authZRequest = {
                target: {
                    action: exports.createActionTarget(request.target.action),
                    subject: exports.createSubjectTarget(request.target.subject),
                    resources: exports.createResourceTarget(request.target.resources, request.target.action)
                },
                context: request.context
            };
            const response = yield cache_1.getOrFill(authZRequest, (req) => __awaiter(this, void 0, void 0, function* () {
                return this.acs.whatIsAllowed(authZRequest);
            }), 'UnAuthZ:whatIsAllowed');
            if (_.isEmpty(response) || _.isEmpty(response.data)) {
                logger_1.default.error('Unexpected empty response from ACS');
            }
            if (response.error) {
                logger_1.default.verbose('Error while requesting authorization to ACS...', { error: response.error.message });
                throw new Error('Error while requesting authorization to ACS');
            }
            return (response.data.policy_sets || []).length > 0 ? response.data.policy_sets[0] : {};
        });
    }
}
exports.UnAuthZ = UnAuthZ;
/**
 * General authorizer. Marshalls data and requests access to the Access Control Service (ACS).
 */
class ACSAuthZ {
    /**
     *
     * @param acs Access Control Service definition (gRPC)
     */
    constructor(acs) {
        this.acs = acs;
    }
    /**
     * Perform request to access-control-srv
     * @param subject
     * @param action
     * @param resource
     */
    isAllowed(request) {
        return __awaiter(this, void 0, void 0, function* () {
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
            let cachePrefix = 'ACSAuthZ';
            if (request.target.subject.id !== undefined) {
                cachePrefix = request.target.subject.id + ':' + cachePrefix;
            }
            if (request.target.action == 'CREATE' || request.target.action == 'MODIFY' || request.target.action == 'DELETE') {
                // insert temporary IDs into resources which are yet to be created if not present in input
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
            // for isAllowed we use the subject, action and resource fields .i.e. reqeust Target
            // since the context resources contains the values which would change for each
            // resource being created and should not be used in key when generating hash
            let cacheKey = {
                target: authZRequest.target
            };
            const response = yield cache_1.getOrFill(cacheKey, (req) => __awaiter(this, void 0, void 0, function* () {
                return this.acs.isAllowed(authZRequest);
            }), cachePrefix + ':isAllowed');
            if (_.isEmpty(response) || _.isEmpty(response.data)) {
                logger_1.default.error(response.error);
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
    }
    /**
    * Perform request to access-control-srv
    * @param subject
    * @param action
    * @param resource
    */
    whatIsAllowed(request) {
        return __awaiter(this, void 0, void 0, function* () {
            const authZRequest = this.prepareRequest(request);
            authZRequest.context = {
                subject: {},
                resources: [],
                security: this.encode(request.context.security)
            };
            let resources = request.target.resources;
            const subject = request.target.subject;
            let cachePrefix = 'ACSAuthZ';
            if (request.target.subject.id !== undefined) {
                cachePrefix = request.target.subject.id + ':' + cachePrefix;
            }
            authZRequest.context.subject = this.encode(subject);
            authZRequest.context.resources = this.encode(resources);
            const response = yield cache_1.getOrFill(authZRequest, (req) => __awaiter(this, void 0, void 0, function* () {
                return this.acs.whatIsAllowed(authZRequest);
            }), cachePrefix + ':whatIsAllowed');
            if (_.isEmpty(response) || _.isEmpty(response.data)) {
                logger_1.default.error('Unexpected empty response from ACS');
            }
            if (response.error) {
                logger_1.default.verbose('Error while requesting authorization to ACS...', { error: response.error.message });
                throw new Error('Error while requesting authorization to ACS');
            }
            return (response.data.policy_sets || []).length > 0 ? response.data.policy_sets[0] : {};
        });
    }
    encode(object) {
        if (_.isArray(object)) {
            return _.map(object, this.encode.bind(this));
        }
        else {
            return {
                value: Buffer.from(JSON.stringify(object))
            };
        }
    }
    prepareRequest(request) {
        let { subject, resources, action } = request.target;
        // this.reduceUserScope(subject);
        const authZRequest = {
            target: {
                action: exports.createActionTarget(action),
                subject: exports.createSubjectTarget(subject),
            },
        };
        if (_.isArray(action)) {
            // whatIsAllowed
            authZRequest.target.resources = exports.createResourceTargetWhatIsAllowed(resources);
        }
        else {
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
            authZRequest.target.resources = exports.createResourceTarget(resources, action);
        }
        return authZRequest;
    }
}
exports.ACSAuthZ = ACSAuthZ;
const acsEvents = [
    'policy_setCreated',
    'policy_setModified',
    'policy_setDeleted',
    'policyCreated',
    'policyModified',
    'policyDeleted',
    'ruleCreated',
    'ruleModified',
    'ruleDeleted',
];
const eventListener = (msg, context, config, eventName) => __awaiter(void 0, void 0, void 0, function* () {
    if (acsEvents.indexOf(eventName) > -1) {
        // no prefix provided, flush complete cache
        logger_1.default.info(`Received event ${eventName} and hence evicting ACS cache`);
        yield cache_1.flushCache();
    }
});
exports.initAuthZ = (config) => __awaiter(void 0, void 0, void 0, function* () {
    if (!exports.authZ) {
        if (config) {
            config_1.updateConfig(config);
        }
        const authzCfg = config_1.cfg.get('authorization');
        const kafkaCfg = config_1.cfg.get('events:kafka');
        // gRPC interface for access-control-srv
        if (authzCfg.enabled) {
            const grpcConfig = config_1.cfg.get('client:acs-srv');
            const client = new grpc_client_1.Client(grpcConfig, logger_1.default);
            const acs = yield client.connect();
            exports.authZ = new ACSAuthZ(acs);
            // listeners for rules / policies / policySets modified, so as to
            // delete the Cache as it would be invalid if ACS resources are modified
            if (kafkaCfg && kafkaCfg.evictACSCache) {
                const events = new kafka_client_1.Events(kafkaCfg, logger_1.default);
                yield events.start();
                for (let topicLabel in kafkaCfg.evictACSCache) {
                    let topicCfg = kafkaCfg.evictACSCache[topicLabel];
                    let topic = events.topic(topicCfg.topic);
                    if (topicCfg.events) {
                        for (let eachEvent of topicCfg.events) {
                            yield topic.on(eachEvent, eventListener);
                        }
                    }
                }
            }
            return exports.authZ;
        }
    }
});
