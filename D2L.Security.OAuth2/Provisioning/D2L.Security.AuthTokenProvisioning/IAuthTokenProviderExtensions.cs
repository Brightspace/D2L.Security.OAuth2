using System.Collections.Generic;
using System.IdentityModel.Tokens;

namespace D2L.Security.AuthTokenProvisioning {
	public static class IAuthTokenProviderExtensions {

		public static IAccessToken ProvisionAccessToken(
			this IAuthTokenProvider @this,
			ClaimSet claimSet,
			IEnumerable<Scope> scopes,
			SecurityToken signingToken
		) {
			var token = @this.ProvisionAccessTokenAsync( claimSet, scopes, signingToken ).Result;
			return token;
		}

	}
}
