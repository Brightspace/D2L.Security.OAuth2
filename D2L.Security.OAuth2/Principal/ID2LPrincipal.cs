using System;
using System.Collections.Generic;
using D2L.Security.OAuth2.Scopes;
using D2L.Security.OAuth2.Validation.AccessTokens;

namespace D2L.Security.OAuth2.Principal {
	public interface ID2LPrincipal {

		/// <summary>
		/// Only valid if the PrincipalType is User
		/// </summary>
		string UserId { get; }

		/// <summary>
		/// Only valid if the PrincipalType is User or Service
		/// </summary>
		Guid TenantId { get; }

		PrincipalType Type { get; }
		IEnumerable<Scope> Scopes { get; }

		IAccessToken AccessToken { get; }
		
	}
}
