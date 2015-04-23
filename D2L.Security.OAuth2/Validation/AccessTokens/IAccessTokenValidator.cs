using System;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Validation.AccessTokens {
	public interface IAccessTokenValidator {

		Task<IValidationResponse> ValidateAsync(
			Uri jwksEndPoint,
			string accessToken
		);

	}
}
