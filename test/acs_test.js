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
const should = require("should");
const resolver_1 = require("../lib/acs/resolver");
const cache_1 = require("../lib/acs/cache");
const grpc_mock_1 = require("grpc-mock");
const interfaces_1 = require("../lib/acs/interfaces");
const authz_1 = require("../lib/acs/authz");
const logger_1 = require("../lib/logger");
const _ = require("lodash");
const lib_1 = require("../lib");
let authZ;
let mockServer;
const permitRule = {
    id: 'permit_rule_id',
    target: {
        action: [],
        resources: [{ id: 'urn:restorecommerce:acs:names:model:entity', 'value': 'urn:test:acs:model:Test.Test' }],
        subject: [
            {
                'id': 'urn:restorecommerce:acs:names:role',
                'value': 'test-role'
            },
            {
                id: 'urn:restorecommerce:acs:names:roleScopingEntity',
                value: 'urn:test:acs:model:organization.Organization'
            },
            {
                id: 'urn:restorecommerce:acs:names:hierarchicalRoleScoping',
                value: 'true'
            }
        ]
    },
    effect: 'PERMIT'
};
const denyRule = {
    id: 'deny_rule_id',
    target: {
        action: [],
        resources: [{ id: 'urn:restorecommerce:acs:names:model:entity', 'value': 'urn:test:acs:model:Test.Test' }],
        subject: [{ 'id': 'urn:restorecommerce:acs:names:role', 'value': 'test-role' }]
    },
    effect: 'DENY'
};
let policySetRQ = {
    policy_sets: [{
            combining_algorithm: 'urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:permit-overrides',
            id: 'test_policy_set_id',
            policies: [
                {
                    combining_algorithm: 'urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:permit-overrides',
                    id: 'test_policy_id',
                    target: {
                        action: [],
                        resources: [{
                                id: 'urn:restorecommerce:acs:names:model:entity',
                                value: 'urn:test:acs:model:Test.Test'
                            }],
                        subject: []
                    }, effect: 'PERMIT',
                    rules: [ // permit or deny rule will be added
                    ],
                    has_rules: true
                }
            ]
        }]
};
const unauthenticatedSubject = [
    {
        id: 'urn:restorecommerce:acs:names:unauthenticated-user',
        value: 'true'
    }
];
const authenticatedSubject = [
    {
        id: "urn:oasis:names:tc:xacml:1.0:subject:subject-id",
        value: "test_user_id"
    },
    {
        id: "urn:restorecommerce:acs:names:roleScopingEntity",
        value: "urn:test:acs:model:organization.Organization"
    },
    {
        id: "urn:restorecommerce:acs:names:roleScopingInstance",
        value: "targetScope"
    }
];
const resources = [
    // resource entity, with resourceID and properties
    { id: 'urn:restorecommerce:acs:names:model:entity', value: 'urn:test:acs:model:Test.Test' },
    { id: 'urn:oasis:names:tc:xacml:1.0:resource:resource-id', value: 'test_id' },
    { id: 'urn:restorecommerce:acs:names:model:property', value: 'urn:test:acs:model:Test.Test#id' },
    { id: 'urn:restorecommerce:acs:names:model:property', value: 'urn:test:acs:model:Test.Test#name' },
    { id: 'urn:restorecommerce:acs:names:model:property', value: 'urn:test:acs:model:Test.Test#description' },
    { id: 'urn:restorecommerce:acs:names:model:property', value: 'urn:test:acs:model:Test.Test#meta' }
];
const createAction = [
    {
        id: 'urn:oasis:names:tc:xacml:1.0:action:action-id',
        value: 'urn:restorecommerce:acs:names:action:create'
    }
];
const readAction = [
    {
        id: 'urn:oasis:names:tc:xacml:1.0:action:action-id',
        value: 'urn:restorecommerce:acs:names:action:read'
    }
];
const encode = (object) => {
    if (_.isArray(object)) {
        return _.map(object, encode);
    }
    else {
        return {
            value: Buffer.from(JSON.stringify(object))
        };
    }
};
const updateMetaData = (resourceList) => {
    if (!_.isArray(resourceList)) {
        resourceList = [resourceList];
    }
    return resourceList.map((resource) => {
        if (!resource.meta) {
            resource.meta = {};
        }
        resource.meta.owner = [
            {
                id: 'urn:restorecommerce:acs:names:ownerIndicatoryEntity',
                value: 'urn:test:acs:model:organization.Organization'
            },
            {
                id: 'urn:restorecommerce:acs:names:ownerInstance',
                value: 'targetScope'
            }
        ];
        return resource;
    });
};
const startGrpcMockServer = (rules) => __awaiter(void 0, void 0, void 0, function* () {
    // Create a mock ACS server to expose isAllowed and whatIsAllowed
    mockServer = grpc_mock_1.createMockServer({
        protoPath: 'test/protos/io/restorecommerce/access_control.proto',
        packageName: 'io.restorecommerce.access_control',
        serviceName: 'Service',
        options: {
            keepCase: true
        },
        rules
    });
    mockServer.listen('0.0.0.0:50061');
    logger_1.default.info('ACS Server started on port 50061');
});
const stopGrpcMockServer = () => __awaiter(void 0, void 0, void 0, function* () {
    yield mockServer.close(() => {
        logger_1.default.info('Server closed successfully');
    });
});
function start() {
    return __awaiter(this, void 0, void 0, function* () {
        // init AuthZ - initialises acs-client connection object
        authZ = (yield authz_1.initAuthZ());
    });
}
function stop() {
    return __awaiter(this, void 0, void 0, function* () {
        // await worker.stop();
    });
}
describe('testing acs-client', () => {
    before(function startServer() {
        return __awaiter(this, void 0, void 0, function* () {
            const cacheEnabled = process.env.CACHE_ENABLED;
            if (cacheEnabled && cacheEnabled.toLowerCase() === 'true') {
                yield cache_1.initializeCache();
            }
            yield start();
        });
    });
    after(function stopServer() {
        return __awaiter(this, void 0, void 0, function* () {
            yield stop();
            yield cache_1.flushCache();
        });
    });
    beforeEach(function flush() {
        return __awaiter(this, void 0, void 0, function* () {
            yield cache_1.flushCache('test_user_id:');
        });
    });
    describe('Test accessRequest', () => {
        it('Should DENY creating Test resource with unauthenticated context', () => __awaiter(void 0, void 0, void 0, function* () {
            startGrpcMockServer([{ method: 'IsAllowed', input: '.*', output: { decision: 'DENY' } },
                { method: 'WhatIsAllowed', input: '.*', output: {} }
            ]);
            // test resrouce to be created
            let testResource = [{
                    id: 'test_id',
                    name: 'Test',
                    description: 'This is a test description'
                }];
            let subject = {
                id: 'test_user_id',
                scope: 'targetScope',
                unauthenticated: true
            };
            testResource = updateMetaData(testResource);
            let response;
            let error;
            try {
                // call accessRequest(), the response is from mock ACS
                response = (yield resolver_1.accessRequest(subject, testResource, interfaces_1.AuthZAction.CREATE, authZ, 'Test'));
            }
            catch (err) {
                error = err;
            }
            should.not.exist(response);
            should.exist(error);
            error.name.should.equal('PermissionDenied');
            error.message.should.equal('permission denied');
            error.details.should.equal('Access not allowed for request with subject:test_user_id, resource:Test, action:CREATE, target_scope:targetScope; the response was DENY');
            error.code.should.equal(403);
            stopGrpcMockServer();
        }));
        it('Should PERMIT creating Test resource with valid user Ctx', () => __awaiter(void 0, void 0, void 0, function* () {
            startGrpcMockServer([{ method: 'IsAllowed', input: '\{.*\:\{.*\:.*\}\}', output: { decision: 'PERMIT' } },
                { method: 'WhatIsAllowed', input: '.*', output: {} }]);
            // test resource to be created
            let testResource = [{
                    id: 'test_id',
                    name: 'Test',
                    description: 'This is a test description'
                }];
            // user ctx data updated in session
            let subject = {
                id: 'test_user_id',
                name: 'test_user',
                scope: 'targetScope',
                role_associations: [
                    {
                        role: 'test-role'
                    }
                ]
            };
            testResource = updateMetaData(testResource);
            // call accessRequest(), the response is from mock ACS
            const response = yield resolver_1.accessRequest(subject, testResource, interfaces_1.AuthZAction.CREATE, authZ, 'Test');
            should.exist(response);
            response.should.equal('PERMIT');
            stopGrpcMockServer();
        }));
        it('Should DENY reading Test resource (DENY rule)', () => __awaiter(void 0, void 0, void 0, function* () {
            // PolicySet contains DENY rule
            policySetRQ.policy_sets[0].policies[0].rules[0] = denyRule;
            startGrpcMockServer([{ method: 'WhatIsAllowed', input: '\{.*\:\{.*\:.*\}\}', output: policySetRQ },
                { method: 'IsAllowed', input: '.*', output: {} }]);
            // test resource to be read of type 'ReadRequest'
            let input = {
                entity: 'Test',
                args: { id: 'test_id' },
                database: 'postgres'
            };
            let subject = {
                id: 'test_user_id',
                scope: 'targetScope',
                role_associations: [
                    {
                        role: 'test-role'
                    }
                ]
            };
            // call accessRequest(), the response is from mock ACS
            let error;
            try {
                yield resolver_1.accessRequest(subject, input, interfaces_1.AuthZAction.READ, authZ);
            }
            catch (err) {
                error = err;
            }
            should.exist(error);
            error.name.should.equal('PermissionDenied');
            error.message.should.equal('permission denied');
            error.details.should.equal('Access not allowed for request with subject:test_user_id, resource:Test, action:READ, target_scope:targetScope; the response was DENY');
            error.code.should.equal(403);
            stopGrpcMockServer();
        }));
        it('Should PERMIT reading Test resource (PERMIT rule) and verify input filter ' +
            'is extended to enforce applicable policies', () => __awaiter(void 0, void 0, void 0, function* () {
            // PolicySet contains PERMIT rule
            policySetRQ.policy_sets[0].policies[0].rules[0] = permitRule;
            startGrpcMockServer([{ method: 'WhatIsAllowed', input: '\{.*\:\{.*\:.*\}\}', output: policySetRQ },
                { method: 'IsAllowed', input: '.*', output: {} }]);
            // test resource to be read of type 'ReadRequest'
            let input = {
                entity: 'Test',
                args: { id: 'test_id' },
                database: 'postgres'
            };
            // user ctx data updated in session
            let subject = {
                id: 'test_user_id',
                scope: 'targetScope',
                role_associations: [
                    {
                        role: 'test-role',
                        attributes: [
                            {
                                id: 'urn:restorecommerce:acs:names:roleScopingEntity',
                                value: 'urn:test:acs:model:organization.Organization'
                            },
                            {
                                id: 'urn:restorecommerce:acs:names:roleScopingInstance',
                                value: 'targetScope'
                            }
                        ]
                    }
                ],
                hierarchical_scopes: [{
                        id: 'targetScope',
                        children: [{
                                id: 'targetSubScope'
                            }]
                    }]
            };
            // call accessRequest(), the response is from mock ACS
            yield resolver_1.accessRequest(subject, input, interfaces_1.AuthZAction.READ, authZ);
            // verify input is modified to enforce the applicapble poilicies
            const filterParamKey = lib_1.cfg.get('authorization:filterParamKey');
            const expectedFilterResponse = { field: filterParamKey, operation: 'eq', value: 'targetScope' };
            const actualResponse = lib_1.toObject(input.args.filter, true);
            actualResponse[0].should.deepEqual(expectedFilterResponse);
            stopGrpcMockServer();
        }));
        it('Should PERMIT reading Test resource (PERMIT rule) with HR scoping enabled and verify input filter ' +
            'is extended to enforce applicable policies', () => __awaiter(void 0, void 0, void 0, function* () {
            // PolicySet contains PERMIT rule
            policySetRQ.policy_sets[0].policies[0].rules[0] = permitRule;
            startGrpcMockServer([{ method: 'WhatIsAllowed', input: '\{.*\:\{.*\:.*\}\}', output: policySetRQ },
                { method: 'IsAllowed', input: '.*', output: {} }]);
            // test resource to be read of type 'ReadRequest'
            let input = {
                entity: 'Test',
                args: { id: 'test_id' },
                database: 'postgres'
            };
            // user ctx data updated in session
            let subject = {
                id: 'test_user_id',
                scope: 'targetSubScope',
                role_associations: [
                    {
                        role: 'test-role',
                        attributes: [
                            {
                                id: 'urn:restorecommerce:acs:names:roleScopingEntity',
                                value: 'urn:test:acs:model:organization.Organization'
                            },
                            {
                                id: 'urn:restorecommerce:acs:names:roleScopingInstance',
                                value: 'targetScope'
                            }
                        ]
                    }
                ],
                hierarchical_scopes: [
                    {
                        id: 'targetScope',
                        children: [{
                                id: 'targetSubScope'
                            }]
                    }
                ]
            };
            // call accessRequest(), the response is from mock ACS
            yield resolver_1.accessRequest(subject, input, interfaces_1.AuthZAction.READ, authZ);
            // verify input is modified to enforce the applicapble poilicies
            const filterParamKey = lib_1.cfg.get('authorization:filterParamKey');
            const expectedFilterResponse = { field: filterParamKey, operation: 'eq', value: 'targetSubScope' };
            const actualFilterResponse = lib_1.toObject(input.args.filter, true);
            actualFilterResponse[0].should.deepEqual(expectedFilterResponse);
            stopGrpcMockServer();
        }));
        it('Should DENY reading Test resource (PERMIT rule) with HR scoping disabled', () => __awaiter(void 0, void 0, void 0, function* () {
            // PolicySet contains PERMIT rule
            // disable HR scoping for permitRule
            permitRule.target.subject[2].value = 'false';
            policySetRQ.policy_sets[0].policies[0].rules[0] = permitRule;
            startGrpcMockServer([{ method: 'WhatIsAllowed', input: '\{.*\:\{.*\:.*\}\}', output: policySetRQ },
                { method: 'IsAllowed', input: '.*', output: {} }]);
            // test resource to be read of type 'ReadRequest'
            let input = {
                entity: 'Test',
                args: { id: 'test_id' },
                database: 'postgres'
            };
            // user ctx data updated in session
            let subject = {
                id: 'test_user_id',
                scope: 'targetSubScope',
                role_associations: [
                    {
                        role: 'test-role',
                        attributes: [
                            {
                                id: 'urn:restorecommerce:acs:names:roleScopingEntity',
                                value: 'urn:test:acs:model:organization.Organization'
                            },
                            {
                                id: 'urn:restorecommerce:acs:names:roleScopingInstance',
                                value: 'targetScope'
                            }
                        ]
                    }
                ],
                hierarchical_scopes: [
                    {
                        id: 'targetScope',
                        children: [{
                                id: 'targetSubScope'
                            }]
                    }
                ]
            };
            // call accessRequest(), the response is from mock ACS
            let error;
            try {
                yield resolver_1.accessRequest(subject, input, interfaces_1.AuthZAction.READ, authZ);
            }
            catch (err) {
                error = err;
            }
            should.exist(error);
            error.name.should.equal('PermissionDenied');
            error.message.should.equal('permission denied');
            error.details.should.equal('Access not allowed for request with subject:test_user_id, resource:Test, action:READ, target_scope:targetSubScope; the response was DENY');
            error.code.should.equal(403);
            stopGrpcMockServer();
            // enable HR scoping for permitRule
            permitRule.target.subject[2].value = 'true';
        }));
    });
    describe('Test isAllowed', () => {
        it('Should DENY creating Test resource with unauthenticated context', () => __awaiter(void 0, void 0, void 0, function* () {
            startGrpcMockServer([{ method: 'isAllowed', input: '.*', output: { decision: 'DENY' } },
                { method: 'WhatIsAllowed', input: '.*', output: {} }]);
            const isAllowedReqUnauth = {
                target: {
                    action: createAction,
                    subject: unauthenticatedSubject,
                    resources
                },
                context: {}
            };
            const response = yield resolver_1.isAllowed(isAllowedReqUnauth, authZ);
            should.exist(response);
            response.should.equal('DENY');
            stopGrpcMockServer();
        }));
        it('Should PERMIT creating Test resource with valid Auth context', () => __awaiter(void 0, void 0, void 0, function* () {
            startGrpcMockServer([{ method: 'isAllowed', input: '.*', output: { decision: 'PERMIT' } },
                { method: 'WhatIsAllowed', input: '.*', output: {} }]);
            const isAllowedReqAuth = {
                target: {
                    action: createAction,
                    subject: authenticatedSubject,
                    resources
                },
                context: {
                    // Need to send encoded subject and resources in context
                    subject: encode(JSON.stringify(authenticatedSubject)),
                    resources: encode(JSON.stringify(resources))
                }
            };
            const response = yield resolver_1.isAllowed(isAllowedReqAuth, authZ);
            ;
            should.exist(response);
            response.should.equal('PERMIT');
            stopGrpcMockServer();
        }));
    });
    describe('Test whatIsAllowed', () => {
        it('Should return applicable policy set for read operation', () => __awaiter(void 0, void 0, void 0, function* () {
            // PolicySet contains DENY rule
            policySetRQ.policy_sets[0].policies[0].rules[0] = permitRule;
            startGrpcMockServer([{ method: 'WhatIsAllowed', input: '\{.*\:\{.*\:.*\}\}', output: policySetRQ },
                { method: 'IsAllowed', input: '.*', output: {} }]);
            const whatIsAllowedReqAuth = {
                target: {
                    action: readAction,
                    subject: authenticatedSubject,
                    resources
                },
                context: {
                    // Need to send encoded subject and resources in context
                    subject: encode(JSON.stringify(authenticatedSubject)),
                    resources: encode(JSON.stringify(resources))
                }
            };
            // call accessRequest(), the response is from mock ACS
            const policySetRQResponse = yield resolver_1.whatIsAllowed(whatIsAllowedReqAuth, authZ);
            should.exist(policySetRQResponse);
            policySetRQResponse.id.should.equal('test_policy_set_id');
            policySetRQResponse.policies.length.should.equal(1);
            policySetRQResponse.policies[0].rules.length.should.equal(1);
            policySetRQResponse.policies[0].rules[0].effect.should.equal('PERMIT');
            stopGrpcMockServer();
        }));
    });
});
