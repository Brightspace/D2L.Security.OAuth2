using System.Collections.Generic;
using System.Security.Claims;

namespace D2L.Security.AuthTokenValidation.TokenValidation {

	/// <summary>
	/// The result of token validation
	/// </summary>
	interface IClaimsPrincipal {
		IEnumerable<Claim> Claims { get; }
	}
}
