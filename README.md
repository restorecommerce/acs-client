# acs-client

<img src="http://img.shields.io/npm/v/%40restorecommerce%2Facs%2Dclient.svg?style=flat-square" alt="">[![Build Status][build]](https://travis-ci.org/restorecommerce/acs-client?branch=master)[![Dependencies][depend]](https://david-dm.org/restorecommerce/acs-client)[![Coverage Status][cover]](https://coveralls.io/github/restorecommerce/acs-client?branch=master)

[version]: http://img.shields.io/npm/v/acs-client.svg?style=flat-square
[build]: http://img.shields.io/travis/restorecommerce/acs-client/master.svg?style=flat-square
[depend]: https://img.shields.io/david/restorecommerce/acs-client.svg?style=flat-square
[cover]: http://img.shields.io/coveralls/restorecommerce/acs-client/master.svg?style=flat-square

* A generic client for [access-control-srv](https://github.com/restorecommerce/access-control-srv)
* It uses [grpc-client](https://github.com/restorecommerce/grpc-client) to access the API's exposed from `access-control-srv` via gRPC interface
* This client constructs the [request](https://github.com/restorecommerce/acs-client/#api-client-interface) object expected by `access-control-srv` when requesting for access to particular [resource](https://github.com/restorecommerce/acs-client/#api-client-interface) and for specific action on it
* This client supports access request for both cases [isAllowed](https://github.com/restorecommerce/access-control-srv#isallowed) and [whatIsAllowed](https://github.com/restorecommerce/access-control-srv#whatisallowed) exposed by `access-control-srv`
* Evaluation of [condition](https://github.com/restorecommerce/access-control-srv#rule) for `whatIsAllowed` request

## Configuration
The `access-control-srv` [URN configurations](https://github.com/restorecommerce/access-control-srv/blob/master/restorecommerce_ABAC.md#urn-reference) needs to be set using [authorization](cfg/config.json) configuration to `acs-client` from access requesting microservice.
The URN for [role scoping entity](https://github.com/restorecommerce/access-control-srv/blob/master/restorecommerce_ABAC.md#role-scoping) for Organization / business units should be set using configuration `authorization.urns.orgScope`.

orgScope: 'urn:<organization>:acs:model:<Entity_Name>'

ex: orgScope: 'urn:restorecommerce:acs:model:organization.Organization'

## API Client Interface
The client exposes `accessRequest` API which constructs the request object and then invoke either `isAllowed` or `whatISAllowed` operation depending on the `action` and returns the response back to calling microservice.

`RequestType`

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| input | `Resource [ ]` or `ReadRequest` | required | list of target resources or read request|
| action | `Enum` | required | action to be performed on the resource (`CREATE`, `READ`, `MODIFY`, `DELETE` or `ALL`) |
| ctx | `Context` | required | context containing [user](https://github.com/restorecommerce/acs-client#user) details (id and role-associations) |
| cb | `Function` | optional | call back function to be called on `PERMIT` of access request |

`Resource`

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| type | string | requried | resource entity name |
| fields | string [ ] | optional | list of fields for accessing or modifying resource |
| instance | string | optional | instance identifier of the resource |

`ReadRequest`

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| entity | string | requried | resource entity name to be read |
| args | [io.restorecommerce.resourcebase.ReadRequest](https://github.com/restorecommerce/resource-base-interface#read) | optional | query arguments |

`ResponseType`

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| output | `Output` or [io.restorecommerce.policy_set.PolicySetRQ](https://github.com/restorecommerce/access-control-srv#whatisallowed) | required | response |


## Tests

// TODO
