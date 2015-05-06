using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

using D2L.Security.OAuth2.Scopes;

namespace D2L.Security.OAuth2.Provisioning {
	public interface IAccessTokenProvider : IDisposable {
		Task<IAccessToken> ProvisionAccessTokenAsync(
			ClaimSet claimSet,
			IEnumerable<Scope> scopes
		);

		Task<IAccessToken> ProvisionAccessTokenAsync(
			IEnumerable<Claim> claims,
			IEnumerable<Scope> scopes
		);
	}
}