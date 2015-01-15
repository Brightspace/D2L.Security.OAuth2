using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.ServiceModel.Security;
using D2L.Security.AuthTokenValidation.PublicKeys;
using D2L.Security.AuthTokenValidation.TokenValidation.Default;

namespace D2L.Security.AuthTokenValidation.TokenValidation {
	internal static class JWTValidatorFactory {

		internal static IJWTValidator Create( string authority ) {
			IPublicKeyProvider keyProvider = PublicKeyProviderFactory.Create( authority );

			SecurityTokenHandlerConfiguration tokenHandlerConfiguration =
				new SecurityTokenHandlerConfiguration();
			tokenHandlerConfiguration.CertificateValidationMode = X509CertificateValidationMode.None;
			tokenHandlerConfiguration.CertificateValidator = X509CertificateValidator.None;

			JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
			tokenHandler.Configuration = tokenHandlerConfiguration;
			
			IJWTValidator validator = new JWTValidator( keyProvider, tokenHandler );
			return validator;
		}
	}
}
