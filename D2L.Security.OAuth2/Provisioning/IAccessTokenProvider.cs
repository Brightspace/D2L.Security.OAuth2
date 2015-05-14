using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

using D2L.Security.OAuth2.Scopes;

namespace D2L.Security.OAuth2.Provisioning {
	
	/// <summary>
	/// Provisions access tokens from the auth service
	/// </summary>
	/// <remarks>This type is disposable</remarks>
	public interface IAccessTokenProvider : IDisposable {

		/// <summary>
		/// Provisions an access token containing the provided claims and scopes.
		/// </summary>
		/// <returns>An access token containing an expiry and the provided claims and scopes.</returns>
		Task<IAccessToken> ProvisionAccessTokenAsync(
			ClaimSet claimSet,
			IEnumerable<Scope> scopes
		);

		/// <summary>
		/// Provisions an access token containing the provided claims and scopes.
		/// </summary>
		/// <returns>An access token containing an expiry and the provided claims and scopes.</returns>
		Task<IAccessToken> ProvisionAccessTokenAsync(
			IEnumerable<Claim> claims,
			IEnumerable<Scope> scopes
		);
	}
}