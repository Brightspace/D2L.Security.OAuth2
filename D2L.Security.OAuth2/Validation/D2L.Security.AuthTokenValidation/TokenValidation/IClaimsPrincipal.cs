using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Principal;

namespace D2L.Security.AuthTokenValidation.TokenValidation {
	interface IClaimsPrincipal : IPrincipal {
		IEnumerable<Claim> Claims { get; }
	}
}
