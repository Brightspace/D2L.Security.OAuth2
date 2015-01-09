using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.ServiceModel.Security;
using D2L.Security.AuthTokenValidation.PublicKeys;

namespace D2L.Security.AuthTokenValidation.TokenValidation.Default {
	internal sealed class JWTValidator : IJWTValidator {

		private readonly IPublicKeyProvider m_keyProvider;

		internal JWTValidator( IPublicKeyProvider keyProvider ) {
			m_keyProvider = keyProvider;
		}

		bool IJWTValidator.TryValidate( string jwt, out IClaimsPrincipal claimsPrincipal ) {

			try {
				claimsPrincipal = ValidateWorker( jwt );
			} catch {
				claimsPrincipal = null;
				return false;
			}

			return true;
		}

		private IClaimsPrincipal ValidateWorker( string jwt ) {

			SecurityTokenHandlerConfiguration tokenHandlerConfiguration = 
				new SecurityTokenHandlerConfiguration();
			tokenHandlerConfiguration.CertificateValidationMode = X509CertificateValidationMode.None;
			tokenHandlerConfiguration.CertificateValidator = X509CertificateValidator.None;
			
			JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
			tokenHandler.Configuration = tokenHandlerConfiguration;

			IPublicKey key = m_keyProvider.Create();

			TokenValidationParameters parameters = new TokenValidationParameters();
			parameters.ValidIssuer = key.Issuer;
			parameters.IssuerSigningKey = key.SecurityKey;
			parameters.ValidateLifetime = true;
			parameters.ValidateAudience = false;
			parameters.ValidateIssuer = true;
			parameters.ValidateIssuerSigningKey = true;

			SecurityToken securityToken;
			ClaimsPrincipal principal = tokenHandler.ValidateToken( jwt, parameters, out securityToken );

			IClaimsPrincipal claimsPrincipal = new ClaimsPrincipalToIClaimsPrincipalAdapter( principal );
			return claimsPrincipal;
		}
	}
}
