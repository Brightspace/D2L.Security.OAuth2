# D2L.Security.ScopeAuthorization

This library facilitates authorization of API scopes. It is meant to be used by API developers for enforcing scope authorization on specific routes (controllers or actions).

## API Scopes
An API scope is an abstraction that specifies an area of functionality of an API. For example, a file service may define scopes for "reading files", "creating files", "listing directories", "deleting directories", etc. It is similar to permissions, but meant for enforcing authorization against client application as opposed to end users.

Scopes are hierarchical. They are composed of three parts: `group:resource:permission[,permission]*`

- **Group**: a group of resources the client is allowed to interact with
- **Resource**: a resource the client is allowed to interact with
- **Permissions**: comma-separated list of permissions granted to a client

For example, a discussions API may define the following scopes:

- Read forums: `discussions:forums:read`
- Read and post topics: `discussions:topics:read,post`
- Reply and subscribe to threads: `discussions:threads:reply,subscribe`

A scope may contain the `*` wildcard character to give wide permissions, e.g.

- Read any resource in discussions: `discussions:*:read`
- Perform any actoin on threads: `discussions:threads:*`
- Perform any action on any resource in discussions: `discussions:*:*`

## ScopeAuthorizeAttribute
The primary construct for enforcing scope authorization is the `ScopeAuthorizeAttribute`.

To enforce authorization on a particular controller or action, just decorate the controller or action with the attribute and specify the required scope parts as parameters:

	[ScopeAuthorizeAttribute(group: "discussions", resource: "threads", permission: "subscribe")]
	public IActionResult SubscribeToThread(int threadId) {
		...
	}

If the client making the request is authorized (i.e. has an access token that includes the required scopes), the attribute will let the request pass through to the controller action. If the client is not granted the required scope, the request will be denied and the client will receive a `403 Forbidden` response with the error message `insufficient_scope`.