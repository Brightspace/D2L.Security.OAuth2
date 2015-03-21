using System.IdentityModel.Tokens;
using D2L.Security.OAuth2.Validation.Token.JwtValidation;

namespace D2L.Security.OAuth2.Validation.Token.Default {

	internal sealed class AuthTokenValidator : IAuthTokenValidator {

		private readonly IJwtValidator m_validator;

		public AuthTokenValidator(
			IJwtValidator validator
			) {
			m_validator = validator;
		}

		ValidationResult IAuthTokenValidator.VerifyAndDecode( 
			string token, 
			out IValidatedToken validatedToken 
			) {
			
			try {
				validatedToken = m_validator.Validate( token );
			} catch ( SecurityTokenExpiredException ) {
				validatedToken = null;
				return ValidationResult.TokenExpired;
			}

			return ValidationResult.Success;
		}
	}
}