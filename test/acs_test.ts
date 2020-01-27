// import * as should from 'should';
// import { accessRequest, parseResourceList, ReadRequest } from '../lib/acs/resolver';
// import { createMockServer } from 'grpc-mock';
// import { AuthZAction, ACSContext, Decision, PolicySetRQ } from '../lib/acs/interfaces';
// import { initAuthZ, ACSAuthZ, UnAuthZ } from '../lib/acs/authz';
// import logger from '../lib/logger';

// let authZ: ACSAuthZ | UnAuthZ;
// let mockServer: any;

// const permitRule = {
//   id: 'permit_rule_id',
//   target: {
//     action: [],
//     resources: [{ id: 'urn:restorecommerce:acs:names:model:entity', 'value': 'urn:test:acs:model:Test.Test' }],
//     subject: [{ 'id': 'urn:restorecommerce:acs:names:role', 'value': 'test-role' }]
//   },
//   effect: 'PERMIT'
// };

// const denyRule = {
//   id: 'deny_rule_id',
//   target: {
//     action: [],
//     resources: [{ id: 'urn:restorecommerce:acs:names:model:entity', 'value': 'urn:test:acs:model:Test.Test' }],
//     subject: [{ 'id': 'urn:restorecommerce:acs:names:role', 'value': 'test-role' }]
//   },
//   effect: 'DENY'
// };

// let policySetRQ = {
//   policy_sets:
//     [{
//       combining_algorithm: 'urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:permit-overrides',
//       id: 'test_policy_set_id',
//       policies: [
//         {
//           combining_algorithm: 'urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:permit-overrides',
//           id: 'test_policy_id',
//           target: {
//             action: [],
//             resources: [{
//               id: 'urn:restorecommerce:acs:names:model:entity',
//               value: 'urn:test:acs:model:Test.Test'
//             }],
//             subject: []
//           }, effect: 'PERMIT',
//           rules: [ // permit or deny rule will be added
//           ],
//           has_rules: true
//         }]
//     }]
// };

// async function startGrpcMockServer(method: string, input: any, output: any) {
//   // Create a mock ACS server to expose isAllowed and whatIsAllowed
//   mockServer = createMockServer({
//     protoPath: 'test/protos/io/restorecommerce/access_control.proto',
//     packageName: 'io.restorecommerce.access_control',
//     serviceName: 'Service',
//     options: {
//       keepCase: true
//     },
//     rules: [
//       {
//         method, input, output
//       }
//     ]
//   });
//   mockServer.listen('0.0.0.0:50061');
//   logger.info('ACS Server started on port 50061');
// }

// async function stopGrpcMockServer() {
//   await mockServer.close(() => {
//     logger.info('Server closed successfully');
//   });
// }

// async function start(): Promise<void> {
//   // init AuthZ
//   await initAuthZ();
//   authZ = require('./../lib/acs/authz');
// }

// async function stop(): Promise<void> {
//   // await worker.stop();
// }

// describe('testing acs-client', () => {
//   before(async function startServer(): Promise<void> {
//     await start();
//   });

//   after(async function stopServer(): Promise<void> {
//     await stop();
//   });

//   describe('Test ACS request', () => {
//     it('Should DENY creating Test resource with unauthenticated context', async () => {
//       startGrpcMockServer('IsAllowed', '.*', { decision: 'DENY' });
//       // test resrouce to be created
//       let testResource = [{
//         id: 'test_id',
//         name: 'Test',
//         description: 'This is a test description'
//       }];
//       // user ctx data updated in session
//       let ctx = ({
//         session: {
//           data: {
//             name: 'test',
//             scope: 'targetScope',
//             unauthenticated: true
//           }
//         }
//       }) as ACSContext;
//       ctx = Object.assign({}, ctx, authZ);
//       // convert data and call accessRequest(), the response is from mock ACS
//       let data = parseResourceList(testResource, AuthZAction.CREATE, 'Test', ctx);
//       let response;
//       let error;
//       try {
//         response = await accessRequest(AuthZAction.CREATE, data, ctx) as Decision;
//       } catch (err) {
//         error = err;
//       }
//       should.not.exist(response);
//       should.exist(error);
//       error.name.should.equal('PermissionDenied');
//       error.message.should.equal('permission denied');
//       error.details.should.equal('Access not allowed for a request from user test for resource Test; the response was DENY');
//       error.code.should.equal('403');
//       stopGrpcMockServer();
//     });
//     it('Should PERMIT creating Test resource with valid user Ctx', async () => {
//       startGrpcMockServer('IsAllowed', '\{.*\:\{.*\:.*\}\}', { decision: 'PERMIT' });
//       // test resource to be created
//       let testResource = [{
//         id: 'test_id',
//         name: 'Test',
//         description: 'This is a test description'
//       }];
//       let ctx = ({
//         session: {
//           data: {
//             id: 'test_id',
//             name: 'test',
//             scope: 'targetScope',
//             role_associations: [
//               {
//                 role: 'test-role'
//               }
//             ]
//           }
//         }
//       }) as ACSContext;
//       ctx = Object.assign({}, ctx, authZ);
//       // convert data and call accessRequest(), the response is from mock ACS
//       let data = parseResourceList(testResource, AuthZAction.CREATE, 'Test', ctx);
//       const response = await accessRequest(AuthZAction.CREATE, data, ctx) as Decision;
//       should.exist(response);
//       response.should.equal('PERMIT');
//       stopGrpcMockServer();
//     });
//     it('Should DENY reading Test resource (DENY rule)', async () => {
//       // PolicySet contains DENY rule
//       policySetRQ.policy_sets[0].policies[0].rules[0] = denyRule;
//       startGrpcMockServer('WhatIsAllowed', '\{.*\:\{.*\:.*\}\}', policySetRQ);
//       // test resource to be read of type 'ReadRequest'
//       let input = {
//         entity: 'Test',
//         args: { id: 'test_id' },
//         database: 'postgres'
//       } as ReadRequest;
//       let ctx = ({
//         session: {
//           data: {
//             id: 'test_id',
//             name: 'test',
//             scope: 'targetScope',
//             role_associations: [
//               {
//                 role: 'test-role'
//               }
//             ]
//           }
//         }
//       }) as ACSContext;
//       ctx = Object.assign({}, ctx, authZ);
//       // call accessRequest(), the response is from mock ACS
//       let error;
//       try {
//         await accessRequest(AuthZAction.READ, input, ctx) as PolicySetRQ;
//       } catch (err) {
//         error = err;
//       }
//       should.exist(error);
//       error.name.should.equal('PermissionDenied');
//       error.message.should.equal('permission denied');
//       error.details.should.equal('Access not allowed for a request from user test for resource Test; the response was DENY');
//       error.code.should.equal('403');
//       stopGrpcMockServer();
//     });
//     it('Should PERMIT reading Test resource (PERMIT rule) and verify input filter ' +
//       'is extended to enforce applicable policies', async () => {
//         // PolicySet contains PERMIT rule
//         policySetRQ.policy_sets[0].policies[0].rules[0] = permitRule;
//         startGrpcMockServer('WhatIsAllowed', '\{.*\:\{.*\:.*\}\}', policySetRQ);
//         // test resource to be read of type 'ReadRequest'
//         let input = {
//           entity: 'Test',
//           args: { id: 'test_id' },
//           database: 'postgres'
//         } as ReadRequest;
//         let ctx = ({
//           session: {
//             data: {
//               id: 'test_id',
//               name: 'test',
//               scope: 'targetScope',
//               role_associations: [
//                 {
//                   role: 'test-role'
//                 }
//               ]
//             }
//           }
//         }) as ACSContext;
//         ctx = Object.assign({}, ctx, authZ);
//         // call accessRequest(), the response is from mock ACS
//         await accessRequest(AuthZAction.READ, input, ctx) as PolicySetRQ;
//         // verify input is modified to enforce the applicapble poilicies
//         const expectedFilterResponse = { field: 'orgKey', operation: 'eq', value: 'targetScope' };
//         input.args.filter[0].should.deepEqual(expectedFilterResponse);
//         stopGrpcMockServer();
//       });
//   });
// });
