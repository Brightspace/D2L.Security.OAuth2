using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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

		// I know this isn't actually an extension, but mrr
		public static SecurityToken CreateSigningToken(
			this IAuthTokenProvider _,
			SecurityKey key,
			Guid keyId
		) {
			var token = new KidSecurityToken(
				keyId.ToString(),
				key
			);

			return token;
		}

	}
}
