using System.IdentityModel.Tokens;
using System.Security.Claims;
using D2L.Security.AuthTokenValidation.PublicKeys;

namespace D2L.Security.AuthTokenValidation.TokenValidation.Default {
	internal sealed class JWTValidator : IJWTValidator {

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

			IClaimsPrincipal claimsPrincipal = new ClaimsPrincipalToIClaimsPrincipalAdapter( principal );
			return claimsPrincipal;
		}
	}
}
