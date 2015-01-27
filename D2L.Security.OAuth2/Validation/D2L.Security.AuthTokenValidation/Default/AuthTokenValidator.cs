using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using D2L.Security.AuthTokenValidation.JwtValidation;

namespace D2L.Security.AuthTokenValidation.Default {

	internal sealed class AuthTokenValidator : IAuthTokenValidator {

		private readonly IJwtValidator m_validator;

		public AuthTokenValidator(
			IJwtValidator validator
			) {
			m_validator = validator;
		}

		ValidationResult IAuthTokenValidator.VerifyAndDecode( string token, out IValidatedToken validatedToken ) {
			try {
				IValidatedJwt validatedJwt = m_validator.Validate( token );
				validatedToken = new ValidatedJwtToValidatedTokenAdapter( validatedJwt );
			} catch ( SecurityTokenExpiredException ) {
				validatedToken = null;
				return ValidationResult.TokenExpired;
			}

			return ValidationResult.Success;
		}
		

		/// <summary>
		/// !!!!!!!!!! REMOVE!!!!!!!!!!!!
		/// </summary>
		/// <param name="validatedJwt"></param>
		/// <param name="sourceJwt"></param>
		/// <returns></returns>
		internal static Principal GetPrincipal( IValidatedJwt validatedJwt, string sourceJwt ) {

			string scopeClaimValue = validatedJwt.Claims
				.Where( x => x.Type == "scope" )
				.Select( x => x.Value )
				.First();
			HashSet<string> scopes = new HashSet<string>( 
				scopeClaimValue.Split( ',' )
				);

			long userId = -1337;
			Claim userIdClaim = validatedJwt.Claims.Where( x => x.Type == "uid" ).FirstOrDefault();
			if( userIdClaim != null ) {
				userId = long.Parse( userIdClaim.Value );
			}

			string tenantId = "00000000-0000-0000-0000-000000000000";
			Claim tenantIdClaim = validatedJwt.Claims.Where( x => x.Type == "tid" ).FirstOrDefault();
			if( tenantIdClaim != null ) {
				tenantId = tenantIdClaim.Value;
			}

			string xsrfToken = "DUMMY XSRF TOKEN!!";
			Claim xsrfClaim = validatedJwt.Claims.Where( x => x.Type == "xt" ).FirstOrDefault();
			if( xsrfClaim != null ) {
				xsrfToken = xsrfClaim.Value;
			}

			Principal principal = new Principal(
				userId,
				tenantId,
				"localhost.com",
				xsrfToken,
				scopes,
				sourceJwt
				);

			return principal;
		}
	}
}