using System;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using D2L.Security.AuthTokenValidation.PublicKeys;

namespace D2L.Security.AuthTokenValidation.TokenValidation.Default {
	internal sealed class JWTValidator : IJWTValidator {

		private const string ALLOWED_SIGNATURE_ALGORITHM = "RS256";
		private readonly IPublicKeyProvider m_keyProvider;

		internal JWTValidator( IPublicKeyProvider keyProvider ) {
			m_keyProvider = keyProvider;
		}

		IClaimsPrincipal IJWTValidator.Validate( string jwt ) {

			JwtSecurityTokenHandler tokenHandler = Helper.CreateTokenHandler();

			IPublicKey key = m_keyProvider.Get();
			TokenValidationParameters validationParameters =
				Helper.CreateValidationParameters( key.Issuer, key.SecurityKey );

			SecurityToken securityToken;
			ClaimsPrincipal principal = tokenHandler.ValidateToken( jwt, validationParameters, out securityToken );

			Type source = securityToken.GetType();
			Type target = typeof( JwtSecurityToken );
			
			if( !target.IsAssignableFrom( source ) ) {
				string message = string.Format(
					"Expected to deserialize token to {0} but was {1}",
					target.AssemblyQualifiedName,
					source.AssemblyQualifiedName
					);
				throw new Exception( message );
			}

			JwtSecurityToken jwtSecurityToken = (JwtSecurityToken)securityToken;

			if( jwtSecurityToken.SignatureAlgorithm != ALLOWED_SIGNATURE_ALGORITHM ) {
				string message = string.Format(
					"Expected signature algorithm {0} but was {1}",
					ALLOWED_SIGNATURE_ALGORITHM,
					jwtSecurityToken.SignatureAlgorithm
					);
				throw new Exception( message );
			}

			IClaimsPrincipal claimsPrincipal = new ClaimsPrincipalToIClaimsPrincipalAdapter( principal );
			return claimsPrincipal;
		}
	}
}
