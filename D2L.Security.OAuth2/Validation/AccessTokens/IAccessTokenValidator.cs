using System;
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
		/// <returns>A <see cref="IValidationResponse"/> holding both the validation status and access token</returns>
		Task<IValidationResponse> ValidateAsync(
			string accessToken
		);
	}
}
