using D2L.Security.AuthTokenValidation.JwtValidation;

namespace D2L.Security.AuthTokenValidation {

	public interface IAuthTokenValidator {
		ValidationResult VerifyAndDecode( string token, out IValidatedToken validatedToken );
	}
}
