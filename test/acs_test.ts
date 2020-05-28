import * as should from 'should';
import { accessRequest, ReadRequest, isAllowed, whatIsAllowed } from '../lib/acs/resolver';
import { flushCache, initializeCache } from '../lib/acs/cache';
import { createMockServer } from 'grpc-mock';
import { AuthZAction, Decision, PolicySetRQ, ACSRequest } from '../lib/acs/interfaces';
import { initAuthZ, ACSAuthZ } from '../lib/acs/authz';
import logger from '../lib/logger';
import * as _ from 'lodash';

let authZ: ACSAuthZ;
let mockServer: any;

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
      }]
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
  policy_sets:
    [{
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
        }]
    }]
};

const unauthenticatedSubject = [
  { // unauthenticated user
    id: 'urn:restorecommerce:acs:names:unauthenticated-user',
    value: 'true'
  }];
const authenticatedSubject = [
  { // authenticated user
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
  { id: 'urn:restorecommerce:acs:names:model:property', value: 'urn:test:acs:model:Test.Test#meta' }];
const createAction = [
  { // action create
    id: 'urn:oasis:names:tc:xacml:1.0:action:action-id',
    value: 'urn:restorecommerce:acs:names:action:create'
  }
];
const readAction = [
  { // action read
    id: 'urn:oasis:names:tc:xacml:1.0:action:action-id',
    value: 'urn:restorecommerce:acs:names:action:read'
  }
];

const encode = (object: any): any => {
  if (_.isArray(object)) {
    return _.map(object, encode);
  } else {
    return {
      value: Buffer.from(JSON.stringify(object))
    };
  }
};

interface serverRule {
  method: string,
  input: any,
  output: any
}

export const parseResourceList = (resourceList: Array<any>, action: AuthZAction,
  entity: string, ctx: ACSContext, resourceNamespace?: string, fields?: string[]): any[] => {
  return resourceList.map((resource): any => {
    let instance = JSON.parse(JSON.stringify(resource));
    if (action == AuthZAction.CREATE || action == AuthZAction.MODIFY || action == AuthZAction.DELETE) {
      if (!instance.meta) {
        instance.meta = {};
      }
      instance.meta.owner = [
        {
          id: 'urn:restorecommerce:acs:names:ownerIndicatoryEntity',
          value: 'urn:test:acs:model:organization.Organization'
        },
        {
          id: 'urn:restorecommerce:acs:names:ownerInstance',
          value: 'targetScope'
        }];
    }
    return {
      fields: fields || _.keys(instance),
      instance,
      type: entity,
      namespace: resourceNamespace
    };
  });
};

const startGrpcMockServer = async (rules: serverRule[]) => {
  // Create a mock ACS server to expose isAllowed and whatIsAllowed
  mockServer = createMockServer({
    protoPath: 'test/protos/io/restorecommerce/access_control.proto',
    packageName: 'io.restorecommerce.access_control',
    serviceName: 'Service',
    options: {
      keepCase: true
    },
    rules
  });
  mockServer.listen('0.0.0.0:50061');
  logger.info('ACS Server started on port 50061');
};

const stopGrpcMockServer = async () => {
  await mockServer.close(() => {
    logger.info('Server closed successfully');
  });
};

async function start(): Promise<void> {
  // init AuthZ - initialises acs-client connection object
  authZ = await initAuthZ() as ACSAuthZ;
}

async function stop(): Promise<void> {
  // await worker.stop();
}

describe('testing acs-client', () => {
  before(async function startServer(): Promise<void> {
    const cacheEnabled = process.env.CACHE_ENABLED;
    if (cacheEnabled && cacheEnabled.toLowerCase() === 'true') {
      await initializeCache();
    }
    await start();
  });

  after(async function stopServer(): Promise<void> {
    await stop();
    await flushCache();
  });

  beforeEach(async function flush() {
    await flushCache('test_user_id:');
  });

  describe('Test accessRequest', () => {
    it('Should DENY creating Test resource with unauthenticated context', async () => {
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
        name: 'test_user',
        scope: 'targetScope',
        unauthenticated: true
      };
      // convert data and call accessRequest(), the response is from mock ACS
      let data = parseResourceList(subject, testResource, AuthZAction.CREATE, 'Test');
      let response;
      let error;
      try {
        response = await accessRequest(subject, data, AuthZAction.CREATE, authZ) as Decision;
      } catch (err) {
        error = err;
      }
      should.not.exist(response);
      should.exist(error);
      error.name.should.equal('PermissionDenied');
      error.message.should.equal('permission denied');
      error.details.should.equal('Access not allowed for request with subject:test_user, resource:Test, action:CREATE, target_scope:targetScope; the response was DENY');
      error.code.should.equal('403');
      stopGrpcMockServer();
    });
    it('Should PERMIT creating Test resource with valid user Ctx', async () => {
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
      // convert data and call accessRequest(), the response is from mock ACS
      let data = parseResourceList(subject, testResource, AuthZAction.CREATE, 'Test');
      const response = await accessRequest(subject, data, AuthZAction.CREATE, authZ) as Decision;
      should.exist(response);
      response.should.equal('PERMIT');
      stopGrpcMockServer();
    });
    it('Should DENY reading Test resource (DENY rule)', async () => {
      // PolicySet contains DENY rule
      policySetRQ.policy_sets[0].policies[0].rules[0] = denyRule;
      startGrpcMockServer([{ method: 'WhatIsAllowed', input: '\{.*\:\{.*\:.*\}\}', output: policySetRQ },
      { method: 'IsAllowed', input: '.*', output: {} }]);
      // test resource to be read of type 'ReadRequest'
      let input = {
        entity: 'Test',
        args: { id: 'test_id' },
        database: 'postgres'
      } as ReadRequest;
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
      // call accessRequest(), the response is from mock ACS
      let error;
      try {
        await accessRequest(subject, input, AuthZAction.READ, authZ) as PolicySetRQ;
      } catch (err) {
        error = err;
      }
      should.exist(error);
      error.name.should.equal('PermissionDenied');
      error.message.should.equal('permission denied');
      error.details.should.equal('Access not allowed for request with subject:test_user, resource:Test, action:READ, target_scope:targetScope; the response was DENY');
      error.code.should.equal('403');
      stopGrpcMockServer();
    });
    it('Should PERMIT reading Test resource (PERMIT rule) and verify input filter ' +
      'is extended to enforce applicable policies', async () => {
        // PolicySet contains PERMIT rule
        policySetRQ.policy_sets[0].policies[0].rules[0] = permitRule;
        startGrpcMockServer([{ method: 'WhatIsAllowed', input: '\{.*\:\{.*\:.*\}\}', output: policySetRQ },
        { method: 'IsAllowed', input: '.*', output: {} }]);
        // test resource to be read of type 'ReadRequest'
        let input = {
          entity: 'Test',
          args: { id: 'test_id' },
          database: 'postgres'
        } as ReadRequest;
        // user ctx data updated in session
        let ctx = ({
          session: {
            data: {
              id: 'test_user_id',
              name: 'test_user',
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
              ]
            }
          ]
        };
        // call accessRequest(), the response is from mock ACS
        await accessRequest(subject, input, AuthZAction.READ, authZ) as PolicySetRQ;
        // verify input is modified to enforce the applicapble poilicies
        const expectedFilterResponse = { field: 'orgKey', operation: 'eq', value: 'targetScope' };
        input.args.filter[0].should.deepEqual(expectedFilterResponse);
        stopGrpcMockServer();
      });
    it('Should PERMIT reading Test resource (PERMIT rule) with HR scoping enabled and verify input filter ' +
      'is extended to enforce applicable policies', async () => {
        // PolicySet contains PERMIT rule
        policySetRQ.policy_sets[0].policies[0].rules[0] = permitRule;
        startGrpcMockServer([{ method: 'WhatIsAllowed', input: '\{.*\:\{.*\:.*\}\}', output: policySetRQ },
        { method: 'IsAllowed', input: '.*', output: {} }]);
        // test resource to be read of type 'ReadRequest'
        let input = {
          entity: 'Test',
          args: { id: 'test_id' },
          database: 'postgres'
        } as ReadRequest;
        // user ctx data updated in session
        let ctx = ({
          session: {
            data: {
              id: 'test_user_id',
              name: 'test_user',
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
              hierarchical_scope: [
                {
                  id: 'targetScope',
                  children: [{
                    id: 'targetSubScope'
                  }]
                }
              ]
            }
          }
        }) as ACSContext;
        // update authZ(client connection object) object in ctx - this
        // is done via middleware in the calling application
        ctx = Object.assign({}, ctx, authZ);
        // call accessRequest(), the response is from mock ACS
        await accessRequest(AuthZAction.READ, input, ctx) as PolicySetRQ;
        // verify input is modified to enforce the applicapble poilicies
        const expectedFilterResponse = { field: 'orgKey', operation: 'eq', value: 'targetSubScope' };
        input.args.filter[0].should.deepEqual(expectedFilterResponse);
        stopGrpcMockServer();
      });
    it('Should DENY reading Test resource (PERMIT rule) with HR scoping disabled', async () => {
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
      } as ReadRequest;
      // user ctx data updated in session
      let ctx = ({
        session: {
          data: {
            id: 'test_user_id',
            name: 'test_user',
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
            hierarchical_scope: [
              {
                id: 'targetScope',
                children: [{
                  id: 'targetSubScope'
                }]
              }
            ]
          }
        }
      }) as ACSContext;
      // update authZ(client connection object) object in ctx - this
      // is done via middleware in the calling application
      ctx = Object.assign({}, ctx, authZ);
      // call accessRequest(), the response is from mock ACS
      let error;
      try {
        await accessRequest(AuthZAction.READ, input, ctx) as PolicySetRQ;
      } catch (err) {
        error = err;
      }
      should.exist(error);
      error.name.should.equal('PermissionDenied');
      error.message.should.equal('permission denied');
      error.details.should.equal('Access not allowed for request with subject:test_user, resource:Test, action:READ, target_scope:targetSubScope; the response was DENY');
      error.code.should.equal('403');
      stopGrpcMockServer();
      // enable HR scoping for permitRule
      permitRule.target.subject[2].value = 'true';
    });
  });
  describe('Test isAllowed', () => {
    it('Should DENY creating Test resource with unauthenticated context', async () => {
      startGrpcMockServer([{ method: 'isAllowed', input: '.*', output: { decision: 'DENY' } },
      { method: 'WhatIsAllowed', input: '.*', output: {} }]);
      const isAllowedReqUnauth = {
        target:
        {
          action: createAction,
          subject: unauthenticatedSubject,
          resources
        },
        context: {}
      } as ACSRequest;
      const response = await isAllowed(isAllowedReqUnauth, authZ);
      should.exist(response);
      response.should.equal('DENY');
      stopGrpcMockServer();
    });
    it('Should PERMIT creating Test resource with valid Auth context', async () => {
      startGrpcMockServer([{ method: 'isAllowed', input: '.*', output: { decision: 'PERMIT' } },
      { method: 'WhatIsAllowed', input: '.*', output: {} }]);
      const isAllowedReqAuth = {
        target:
        {
          action: createAction,
          subject: authenticatedSubject,
          resources
        },
        context: {
          // Need to send encoded subject and resources in context
          subject: encode(JSON.stringify(authenticatedSubject)),
          resources: encode(JSON.stringify(resources))
        }
      } as ACSRequest;
      const response = await isAllowed(isAllowedReqAuth, authZ);;
      should.exist(response);
      response.should.equal('PERMIT');
      stopGrpcMockServer();
    });
  });
  describe('Test whatIsAllowed', () => {
    it('Should return applicable policy set for read operation', async () => {
      // PolicySet contains DENY rule
      policySetRQ.policy_sets[0].policies[0].rules[0] = permitRule;
      startGrpcMockServer([{ method: 'WhatIsAllowed', input: '\{.*\:\{.*\:.*\}\}', output: policySetRQ },
      { method: 'IsAllowed', input: '.*', output: {} }]);
      const whatIsAllowedReqAuth = {
        target:
        {
          action: readAction,
          subject: authenticatedSubject,
          resources
        },
        context: {
          // Need to send encoded subject and resources in context
          subject: encode(JSON.stringify(authenticatedSubject)),
          resources: encode(JSON.stringify(resources))
        }
      } as ACSRequest;
      // call accessRequest(), the response is from mock ACS
      const policySetRQResponse = await whatIsAllowed(whatIsAllowedReqAuth, authZ);
      should.exist(policySetRQResponse);
      policySetRQResponse.id.should.equal('test_policy_set_id');
      policySetRQResponse.policies.length.should.equal(1);
      policySetRQResponse.policies[0].rules.length.should.equal(1);
      policySetRQResponse.policies[0].rules[0].effect.should.equal('PERMIT');
      stopGrpcMockServer();
    });
  });
});
