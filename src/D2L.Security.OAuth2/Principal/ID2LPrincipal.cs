using System;
using System.Collections.Generic;
using D2L.Security.OAuth2.Scopes;
using D2L.Security.OAuth2.Validation.AccessTokens;
using static D2L.CodeStyle.Annotations.Objects;

namespace D2L.Security.OAuth2.Principal {
	/// <summary>
	/// Principal class that is D2L-specific
	/// </summary>
	[Immutable]
	public interface ID2LPrincipal {
		/// <summary>
		/// Only valid if the <see cref="Type"/> is User
		/// </summary>
		long UserId { get; }

		/// <summary>
		/// If this doesn't equal UserId it means that impersonation is going on and
		/// this is the userId of the impersonator.
		/// Only valid if the <see cref="Type"/> is User.
		/// </summary>
		long ActualUserId { get; }

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
		/// 
		/// </summary>
		IAccessToken AccessToken { get; }
	}
}