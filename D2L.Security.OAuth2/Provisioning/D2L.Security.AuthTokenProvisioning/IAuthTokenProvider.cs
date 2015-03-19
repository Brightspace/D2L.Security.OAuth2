using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Threading.Tasks;

namespace D2L.Security.AuthTokenProvisioning {
	
	public interface IAuthTokenProvider : IDisposable {

		Task<IAccessToken> ProvisionAccessTokenAsync(
			ClaimSet claimSet,
			IEnumerable<Scope> scopes,
			SecurityToken signingToken
		);

	}
}