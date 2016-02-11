using System.Collections.Generic;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Scopes;

namespace D2L.Security.OAuth2.Provisioning.Default {
	
	/// <summary>
	/// Calls the Auth Service to provision access tokens
	/// </summary>
	/// <remarks>This type is disposable</remarks>
	internal interface IAuthServiceClient {

		/// <summary>
		/// Provisions an access token from the auth service
		/// </summary>
		/// <param name="assertion">A JWT signed by the private key of the entity requesting the token</param>
		/// <param name="scopes">List of scopes to include in the access token</param>
		/// <returns>A JWT token from the auth service signed with the auth service's private key</returns>
		/// <exception cref="AuthServiceException">
		/// The auth service could not be reached, or it did not respond with
		/// a status code indicating success.
		/// </exception>
		Task<IAccessToken> ProvisionAccessTokenAsync(
			string assertion,
			IEnumerable<Scope> scopes
		);
	}
}
