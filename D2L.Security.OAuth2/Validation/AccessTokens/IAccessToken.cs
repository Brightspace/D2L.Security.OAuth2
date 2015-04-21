using System;
using System.Collections.Generic;
using System.Security.Claims;

namespace D2L.Security.OAuth2.Validation.AccessTokens {
	public interface IAccessToken {

		string Id { get; }

		/// <summary>
		/// The raw, signed access token.  Treat it like a password (for example, do not Log).
		/// </summary>
		string SensitiveRawAccessToken { get; }
		
		IEnumerable<Claim> Claims { get; }

		/// <summary>
		/// Expiry in UTC
		/// </summary>
		DateTime Expiry { get; }

	}
}
