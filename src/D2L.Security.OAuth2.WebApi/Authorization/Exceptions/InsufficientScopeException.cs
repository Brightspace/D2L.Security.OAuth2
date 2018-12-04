using System;
using D2L.Security.OAuth2.Scopes;

namespace D2L.Security.OAuth2.Authorization.Exceptions {
	internal sealed class InsufficientScopeException : OAuth2Exception {

		internal InsufficientScopeException( Scope scope, Exception innerException = null ) : base(
			error: OAuth2Exception.Type.insufficient_scope,
			errorDescription: $"Required scope: '{ scope }'",
			innerException: innerException
		) {
			Scope = scope;
		}

		internal Scope Scope { get; }

	}
}
