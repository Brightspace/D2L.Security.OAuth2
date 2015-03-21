using D2L.Security.OAuth2.Validation.Token.JwtValidation;

namespace D2L.Security.OAuth2.Validation.Token {

	public interface IAuthTokenValidator {
		ValidationResult VerifyAndDecode( string token, out IValidatedToken validatedToken );
	}
}
