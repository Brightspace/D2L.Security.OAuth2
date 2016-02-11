using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Validation.AccessTokens {

	/// <summary>
	/// An abstraction for validating access tokens
	/// </summary>
	public interface IAccessTokenValidator {

		/// <summary>
		/// Validates an access token
		/// </summary>
		/// <param name="accessToken">The raw token to validate</param>
		/// <returns>A <see cref="IAccessToken"/> holding the decoded and validated access token</returns>
		/// <remarks>Throws <see cref="Exceptions.ValidationException"/> on error</remarks>
		Task<IAccessToken> ValidateAsync(
			string accessToken
		);
	}
}
