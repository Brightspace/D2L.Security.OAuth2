using System;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.ServiceModel.Security;

namespace D2L.Security.OAuth2.Tests.Unit.Provisioning.Default {
	
	internal sealed partial class AccessTokenProviderTests {

		private static void MakeKeyPair( out byte[] privateKey, out byte[] publicKey, out Guid keyId ) {
			using( RSACryptoServiceProvider rsaService = MakeCryptoServiceProvider() ) {
				privateKey = rsaService.ExportCspBlob( true );
				publicKey = rsaService.ExportCspBlob( false );
				keyId = Guid.NewGuid();
			}
		}

		private static RSACryptoServiceProvider MakeCryptoServiceProvider() {
			RSACryptoServiceProvider rsaService = new RSACryptoServiceProvider( 2048 );
			rsaService.PersistKeyInCsp = false;
			return rsaService;
		}

		private static ISecurityTokenValidator CreateTokenHandler() {
			SecurityTokenHandlerConfiguration tokenHandlerConfiguration =
				new SecurityTokenHandlerConfiguration();
			tokenHandlerConfiguration.CertificateValidationMode = X509CertificateValidationMode.None;
			tokenHandlerConfiguration.CertificateValidator = X509CertificateValidator.None;

			JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
			tokenHandler.Configuration = tokenHandlerConfiguration;

			return tokenHandler;
		}

		private static TokenValidationParameters CreateTokenValidationParameters( SecurityKey securityKey ) {
			TokenValidationParameters validationParameters = new TokenValidationParameters();
			validationParameters.IssuerSigningKeyResolver = (_, __, ___, ____) => securityKey;
			validationParameters.ValidateIssuerSigningKey = true;
			validationParameters.ValidateLifetime = false;
			validationParameters.ValidateIssuer = false;
			validationParameters.ValidateAudience = false;
			validationParameters.ValidateActor = false;
			
			return validationParameters;
		}
	}
}
