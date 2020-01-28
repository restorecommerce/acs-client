# acs-client

<img src="http://img.shields.io/npm/v/%40restorecommerce%2Facs%2Dclient.svg?style=flat-square" alt="">[![Build Status][build]](https://travis-ci.org/restorecommerce/acs-client?branch=master)[![Dependencies][depend]](https://david-dm.org/restorecommerce/acs-client)[![Coverage Status][cover]](https://coveralls.io/github/restorecommerce/acs-client?branch=master)

[version]: http://img.shields.io/npm/v/acs-client.svg?style=flat-square
[build]: http://img.shields.io/travis/restorecommerce/acs-client/master.svg?style=flat-square
[depend]: https://img.shields.io/david/restorecommerce/acs-client.svg?style=flat-square
[cover]: http://img.shields.io/coveralls/restorecommerce/acs-client/master.svg?style=flat-square

Features:

- A generic client for the [access-control-srv](https://github.com/restorecommerce/access-control-srv).
- It uses [grpc-client](https://github.com/restorecommerce/grpc-client) to access the exposed API via its gRPC interface.
- This client constructs the [request](https://github.com/restorecommerce/acs-client/#api-client-interface) object expected by `access-control-srv` when requesting access to a particular [resource](https://github.com/restorecommerce/acs-client/tree/acs-tests#accessrequest) with a specific action on it.
- This client supports access request for both methods [isAllowed](https://github.com/restorecommerce/access-control-srv#isallowed) and [whatIsAllowed](https://github.com/restorecommerce/access-control-srv#whatisallowed) exposed by `access-control-srv`.
- It evaluates the [condition](https://github.com/restorecommerce/access-control-srv#rule) for `whatIsAllowed` requests.
- It returns the decision made by the ACS.

## Configuration

The `access-control-srv` [URN configurations](https://github.com/restorecommerce/access-control-srv/blob/master/restorecommerce_ABAC.md#urn-reference) needs to be set using [authorization](cfg/config.json#L85) configuration to `acs-client` from access requesting microservice.
The URN for [role scoping entity](https://github.com/restorecommerce/access-control-srv/blob/master/restorecommerce_ABAC.md#role-scoping) for Organization/ business units should be set using configuration property `authorization.urns.orgScope`.

orgScope: 'urn:\<organization\>:acs:model:<Entity_Name>'

ex: orgScope: 'urn:restorecommerce:acs:model:organization.Organization'

The applicable policies / rules can be enforced on the request using [`enforce`](cfg/config.json#L88) configuration

## API

The client exposes the following api's:

### accessRequest

It turns an API request as can be found in typical Web frameworks like express, koa etc. into a proper ACS request. For write operations it uses [isAllowed](https://github.com/restorecommerce/access-control-srv#isallowed) and for read operations it uses [whatIsAllowed](https://github.com/restorecommerce/access-control-srv#whatisallowed) operation from [access-control-srv](https://github.com/restorecommerce/access-control-srv). 
Requests are performed providing `Request` message as input and response is `Response` message type. For the read operations it extends the filter provided in the `ReadRequst` of the input message to enforce the applicapble poilicies. The response is `Decision` or policy set reverse query `PolicySetRQ` depending on the requeste operation `isAllowed()` or `whatIsAllowed()` respectively.

`Request`

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| action | `Enum` | required | action to be performed on the resource (`CREATE`, `READ`, `MODIFY`, `DELETE` or `ALL`) |
| request | `Resource` or `Resource [ ]` or `ReadRequest` | required | list of target resources or read request|
| ctx | `Context` | required | context containing [user](https://github.com/restorecommerce/acs-client#user) details (ID and role-associations) |
 
 `Response`

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| Decision | `Decision` | optional | Access decision; possible values are `PERMIT`, `DENY` or `INDETERMINATE` |
| PolicySetRQ | `PolicySetRQ [ ]` | optional | List of applicable policy sets |

`Resource`

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| type | string | requried | resource entity name |
| fields | string [ ] | optional | list of fields for accessing or modifying resource |
| instance | string | optional | instance identifier of the resource |
| namespace | string | optional | namespace prefix for resource entity |

`ReadRequest`

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| entity | string | requried | resource entity name to be read |
| args | [io.restorecommerce.resourcebase.ReadRequest](https://github.com/restorecommerce/resource-base-interface#read) | optional | query arguments |
| database | string | optional | database for read request, currently `arangodb` and `postgres` are supported |
| namespace | string | optional | namespace prefix for resource entity |

`Decision`

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| decision | `io.restorecommerce.access_control.Decision` | required | Access decision; possible values are `PERMIT`, `DENY` or `INDETERMINATE` |

`PolicySetRQ`

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| policy_sets | [ ] [`io.restorecommerce.policy_set.PolicySetRQ`](https://github.com/restorecommerce/access-control-srv#whatisallowed) | required | List of applicable policy sets |

### isAllowed

This API exposes the [`isAllowed`](https://github.com/restorecommerce/access-control-srv#isallowed) api of `access-control-srv` and retruns the response as `Decision`.
Requests are performed providing [`io.restorecommerce.access_control.Request`](https://github.com/restorecommerce/access-control-srv#isallowed) message as input and response is [`io.restorecommerce.access_control.Response`](https://github.com/restorecommerce/access-control-srv#isallowed) message.

### whatIsAllowed

This API exposes the [`isAllowed`](https://github.com/restorecommerce/access-control-srv#whatisallowed) api of `access-control-srv` and retruns the response as `Decision`. Requests are performed providing [`io.restorecommerce.access_control.Request`](https://github.com/restorecommerce/access-control-srv#whatisallowed) message as input and response is [`io.restorecommerce.access_control.ReverseQuery`](https://github.com/restorecommerce/access-control-srv#whatisallowed) message.

## Usage

For a simple example on how to use this client with a `access-control-srv` check the [test cases](https://github.com/restorecommerce/acs-client/blob/acs-tests/test/acs_test.ts).

- Install dependencies

```sh
npm install
```

- Build

```sh
# compile the code
npm run build
```

- Run tests

```sh
# run the tests
npm run test
```