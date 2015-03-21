using System;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using D2L.Security.OAuth2.Validation.Token.JwtValidation.Exceptions;
using D2L.Security.OAuth2.Validation.Token.PublicKeys;

namespace D2L.Security.OAuth2.Validation.Token.JwtValidation.Default {
	internal sealed class JwtValidator : IJwtValidator {

		private readonly IPublicKeyProvider m_keyProvider;
		private readonly ISecurityTokenValidator m_tokenHandler;

		internal JwtValidator( 
			IPublicKeyProvider keyProvider,
			ISecurityTokenValidator tokenHandler
			) {
			m_keyProvider = keyProvider;
			m_tokenHandler = tokenHandler;
		}

		IValidatedToken IJwtValidator.Validate( string jwt ) {

			if( String.IsNullOrEmpty( jwt ) ) {
				throw new ArgumentException( "Cannot be null or empty", jwt );
			}

			IPublicKey key = m_keyProvider.Get();
			TokenValidationParameters validationParameters =
				JwtHelper.CreateValidationParameters( key.Issuer, key.SecurityKey );

			SecurityToken securityToken;
			ClaimsPrincipal principal = m_tokenHandler.ValidateToken( jwt, validationParameters, out securityToken );
			
			JwtSecurityToken jwtSecurityToken = (JwtSecurityToken)securityToken;

			if( jwtSecurityToken.SignatureAlgorithm != Constants.ALLOWED_SIGNATURE_ALGORITHM ) {
				string message = string.Format(
					"Expected signature algorithm {0} but was {1}",
					Constants.ALLOWED_SIGNATURE_ALGORITHM,
					jwtSecurityToken.SignatureAlgorithm
					);
				throw new InvalidTokenTypeException( message );
			}

			IValidatedToken validatedJwt = new ValidatedJwt( jwtSecurityToken );
			return validatedJwt;
		}
	}
}
