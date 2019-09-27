# acs-client

* A generic client for [access-control-srv](https://github.com/restorecommerce/access-control-srv)
* It uses [grpc-client](https://github.com/restorecommerce/grpc-client) to access the API's exposed from `access-control-srv` via gRPC interface
* This client constructs the request object expected by `access-control-srv` when client reqeusts for access to particular resource and for specific action on resource
* This client supports access request for both cases [isAllowed](https://github.com/restorecommerce/access-control-srv#isallowed) and [whatIsAllowed](https://github.com/restorecommerce/access-control-srv#whatisallowed) exposed by `access-control-srv`
* Evaluation of [condition](https://github.com/restorecommerce/access-control-srv#rule) for `whatIsAllowed` request

## Configuration:
The `access-control-srv` [URN configurations](https://github.com/restorecommerce/access-control-srv/blob/master/restorecommerce_ABAC.md#urn-reference) needs to be set using [authorization](cfg/config.json) configuration to `acs-client` from access requesting microservice.
The URN for [role scoping entity](https://github.com/restorecommerce/access-control-srv/blob/master/restorecommerce_ABAC.md#role-scoping) for Organization / business units should be set using configuration `authorization.urns.orgScope`.

orgScope: 'urn:<organization>:acs:model:<Entity_Name>'

ex: orgScope: 'urn:restorecommerce:acs:model:organization.Organization'

## API Client Interface:
The client exposes `accessRequest` API which constructs the request object and then invoke either `isAllowed` or `whatISAllowed` operation depending on the `action` and returns the response back to calling microservice.

`RequestType`

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| input | `Resource [ ]` or `ReadRequest` | required | list of target resources or read request|
| action | string | required | action to be performed on the resource (`create`, `read`, `modify` or `delete`) |
| ctx | `Context` | required | context containing [user](https://github.com/restorecommerce/identity-srv#user) details (id and role-associations) |
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


Tests:

// TODO
