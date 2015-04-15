using System;
using System.Collections.Generic;
using System.Security.Claims;
using D2L.Security.OAuth2.Scopes;
using D2L.Security.OAuth2.Validation.Request;

namespace D2L.Security.OAuth2 {
	public interface ID2LPrincipal {
		string UserId { get; }
		string TenantId { get; }
		string TenantUrl { get; }

		PrincipalType Type { get; }

		IEnumerable<Scope> Scopes { get; }
		IEnumerable<Claim> AllClaims { get; }

		/// <summary>
		/// The expiration date of the access token provided with the request
		/// </summary>
		DateTime AccessTokenExpiry { get; }

		string Xsrf { get; }

		string AccessToken { get; }
	}
}
