using System;
using System.Collections.Generic;
using System.Security.Claims;

namespace D2L.Security.AuthTokenValidation.JwtValidation {

	/// <summary>
	/// A token which can be trusted to have been validated
	/// </summary>
	interface IValidatedJwt {
		IEnumerable<Claim> Claims { get; }

		/// <summary>
		/// Expiry in UTC standard time
		/// </summary>
		DateTime Expiry { get; }
	}
}
