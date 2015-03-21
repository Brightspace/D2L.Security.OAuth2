using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.ServiceModel.Security;

namespace D2L.Security.OAuth2.Validation.Token.JwtValidation.Default {
	internal static class JwtHelper {

		internal static ISecurityTokenValidator CreateTokenHandler() {
			SecurityTokenHandlerConfiguration tokenHandlerConfiguration =
				new SecurityTokenHandlerConfiguration();
			tokenHandlerConfiguration.CertificateValidationMode = X509CertificateValidationMode.None;
			tokenHandlerConfiguration.CertificateValidator = X509CertificateValidator.None;

			JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
			tokenHandler.Configuration = tokenHandlerConfiguration;

			return tokenHandler;
		}

		internal static TokenValidationParameters CreateValidationParameters( 
			string issuer,
			SecurityKey issuerKey
			) {

			TokenValidationParameters parameters = new TokenValidationParameters();
			parameters.ValidIssuer = issuer;
			parameters.IssuerSigningKey = issuerKey;
			parameters.ValidateLifetime = true;
			parameters.ValidateIssuerSigningKey = true;
			parameters.ValidateIssuer = true;

			parameters.ValidateAudience = false;
			parameters.ValidateActor = false;

			return parameters;
		}
	}
}
