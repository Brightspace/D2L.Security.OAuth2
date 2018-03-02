using System;
using System.Collections.Generic;
using System.Security.Claims;
using static D2L.CodeStyle.Annotations.Objects;

namespace D2L.Security.OAuth2.Validation.AccessTokens {

	/// <summary>
	/// A strongly-typed version of the access token
	/// </summary>
	[Immutable]
	public interface IAccessToken {

		/// <summary>
		/// The JWT ID (JTI)
		/// </summary>
		string Id { get; }

		/// <summary>
		/// The raw, signed access token. Treat it like a password (for example, do not log).
		/// </summary>
		string SensitiveRawAccessToken { get; }

		/// <summary>
		/// Claims associated with this token
		/// </summary>
		IEnumerable<Claim> Claims { get; }

		/// <summary>
		/// Expiry in UTC
		/// </summary>
		DateTime Expiry { get; }

	}
}