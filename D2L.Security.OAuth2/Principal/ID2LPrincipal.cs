using System;
using System.Collections.Generic;
using D2L.Security.OAuth2.Scopes;
using D2L.Security.OAuth2.Validation.AccessTokens;

namespace D2L.Security.OAuth2.Principal {

	/// <summary>
	/// Principal class that is D2L-specific
	/// </summary>
	public interface ID2LPrincipal {

		/// <summary>
		/// Only valid if the <see cref="Type"/> is User
		/// </summary>
		string UserId { get; }

		/// <summary>
		/// Only valid if the <see cref="Type"/> is User or Service
		/// </summary>
		Guid TenantId { get; }

		/// <summary>
		/// The type of principal
		/// </summary>
		PrincipalType Type { get; }

		/// <summary>
		/// Scopes that the principal is authorized for
		/// </summary>
		IEnumerable<Scope> Scopes { get; }

		/// <summary>
		/// The access token that the principal was constructed from
		/// </summary>
		IAccessToken AccessToken { get; }
	}
}
