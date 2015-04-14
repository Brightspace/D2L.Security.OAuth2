using System;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Validation.AccessTokens {
	public interface IAccessTokenValidator {

		Task<ValidationResponse> ValidateAsync(
			Uri jwksEndPoint,
			string accessToken
		);

	}
}
