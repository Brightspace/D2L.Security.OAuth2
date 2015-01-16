using System;
using System.Collections.Generic;
using System.Security.Claims;

namespace D2L.Security.AuthTokenValidation.TokenValidation {

	/// <summary>
	/// A token which can be trusted to have been validated
	/// </summary>
	interface IValidatedJWT {
		IEnumerable<Claim> Claims { get; }

		/// <summary>
		/// Expiry in UTC standard time
		/// </summary>
		DateTime Expiry { get; }
	}
}
