using D2L.CodeStyle.Annotations;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Validation.AccessTokens {

	/// <summary>
	/// An abstraction for validating access tokens
	/// </summary>
	public partial interface IAccessTokenValidator {

		/// <summary>
		/// Perform steps to potentially make future validations faster.
		/// </summary>
		[GenerateSync]
		Task PrefetchAsync();

		/// <summary>
		/// Validates an access token
		/// </summary>
		/// <param name="accessToken">The raw token to validate</param>
		/// <returns>A <see cref="IAccessToken"/> holding the decoded and validated access token</returns>
		/// <remarks>Throws <see cref="Exceptions.ValidationException"/> on error</remarks>
		[GenerateSync]
		Task<IAccessToken> ValidateAsync(
			string accessToken
		);

	}
}
