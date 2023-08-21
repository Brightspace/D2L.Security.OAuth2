using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using D2L.CodeStyle.Annotations;
using D2L.Security.OAuth2.Caching;
using D2L.Security.OAuth2.Scopes;

namespace D2L.Security.OAuth2.Provisioning {

	/// <summary>
	/// Provisions access tokens from the auth service
	/// </summary>
	/// <remarks>This type is disposable</remarks>
	public partial interface IAccessTokenProvider {

		/// <summary>
		/// Provisions an access token containing the provided claims and scopes.
		/// </summary>
		/// <param name="claimSet">The set of claims to be included in the token.</param>
		/// <param name="scopes">The set of scopes to be included in the token.</param>
		/// <param name="cache">The provided <see cref="ICache"/> does not need to 
		/// check for token expiration or grace period because the 
		/// <see cref="IAccessTokenProvider"/> will handle it internally.</param>
		/// <returns>An access token containing an expiry and the provided claims and scopes.</returns>
		[GenerateSync]
		Task<IAccessToken> ProvisionAccessTokenAsync(
			ClaimSet claimSet,
			IEnumerable<Scope> scopes,
			ICache cache = null
		);

		/// <summary>
		/// Provisions an access token containing the provided claims and scopes.
		/// </summary>
		/// <param name="claims">The set of claims to be included in the token.</param>
		/// <param name="scopes">The set of scopes to be included in the token.</param>
		/// <param name="cache">The provided <see cref="ICache"/> does not need to 
		/// check for token expiration or grace period because the 
		/// <see cref="IAccessTokenProvider"/> will handle it internally.</param>
		/// <returns>An access token containing an expiry and the provided claims and scopes.</returns>
		[GenerateSync]		
		Task<IAccessToken> ProvisionAccessTokenAsync(
			IEnumerable<Claim> claims,
			IEnumerable<Scope> scopes,
			ICache cache = null
		);
	}
}
