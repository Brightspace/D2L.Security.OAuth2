using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using D2L.CodeStyle.Annotations;
using D2L.Security.OAuth2.Scopes;

namespace D2L.Security.OAuth2.Provisioning.Default {

	internal partial interface INonCachingAccessTokenProvider {

		[GenerateSync]
		Task<IAccessToken> ProvisionAccessTokenAsync(
			ClaimSet claimSet,
			IEnumerable<Scope> scopes
		);

		[GenerateSync]
		Task<IAccessToken> ProvisionAccessTokenAsync(
			IEnumerable<Claim> claims,
			IEnumerable<Scope> scopes
		);
	}
}
