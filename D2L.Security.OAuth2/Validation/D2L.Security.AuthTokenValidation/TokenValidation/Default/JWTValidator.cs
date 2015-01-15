using System;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using D2L.Security.AuthTokenValidation.PublicKeys;
using D2L.Security.AuthTokenValidation.TokenValidation.Exceptions;

namespace D2L.Security.AuthTokenValidation.TokenValidation.Default {
	internal sealed class JWTValidator : IJWTValidator {

		private const string ALLOWED_SIGNATURE_ALGORITHM = "RS256";
		private const string ALLOWED_TOKEN_TYPE = "JWT";

		private readonly IPublicKeyProvider m_keyProvider;
		private readonly ISecurityTokenValidator m_tokenHandler;

		internal JWTValidator( 
			IPublicKeyProvider keyProvider,
			ISecurityTokenValidator tokenHandler
			) {
			m_keyProvider = keyProvider;
			m_tokenHandler = tokenHandler;
		}

		IValidatedJWT IJWTValidator.Validate( string jwt ) {

			if( jwt == null ) {
				throw new ArgumentException( "Cannot be null", jwt );
			}

			IPublicKey key = m_keyProvider.Get();
			TokenValidationParameters validationParameters =
				Helper.CreateValidationParameters( key.Issuer, key.SecurityKey );

			SecurityToken securityToken;
			ClaimsPrincipal principal = m_tokenHandler.ValidateToken( jwt, validationParameters, out securityToken );

			//Type source = securityToken.GetType();
			//Type target = typeof( JwtSecurityToken );
			
			//if( !target.IsAssignableFrom( source ) ) {
			//	string message = string.Format(
			//		"Expected to deserialize token to {0} but was {1}",
			//		target.AssemblyQualifiedName,
			//		source.AssemblyQualifiedName
			//		);
			//	throw new Exception( message );
			//}

			JwtSecurityToken jwtSecurityToken = (JwtSecurityToken)securityToken;

			if( jwtSecurityToken.SignatureAlgorithm != ALLOWED_SIGNATURE_ALGORITHM ) {
				string message = string.Format(
					"Expected signature algorithm {0} but was {1}",
					ALLOWED_SIGNATURE_ALGORITHM,
					jwtSecurityToken.SignatureAlgorithm
					);
				throw new InvalidTokenTypeException( message );
			}

			string tokenType = jwtSecurityToken.Header.Typ;
			if( tokenType != ALLOWED_TOKEN_TYPE ) {
				string message = string.Format(
					"Expected token type {0} but was {1}",
					ALLOWED_TOKEN_TYPE,
					tokenType
					);
				throw new Exception( message );
			}

			IValidatedJWT validatedJWT = new ValidatedJWT( jwtSecurityToken );
			return validatedJWT;
		}
	}
}
