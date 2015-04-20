using System.Collections.Generic;
using D2L.Security.OAuth2.Scopes;
using D2L.Security.OAuth2.Validation.AccessTokens;

namespace D2L.Security.OAuth2.Principal {
	public interface ID2LPrincipal {

		string UserId { get; }
		string TenantId { get; }

		PrincipalType Type { get; }
		IEnumerable<Scope> Scopes { get; }

		IAccessToken AccessToken { get; }
		
	}
}
