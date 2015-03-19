using System;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;
using System.ServiceModel.Security;
using D2L.Security.AuthTokenProvisioning.Default;
using D2L.Security.AuthTokenProvisioning.Tests.Utilities;
using Moq;
using NUnit.Framework;

namespace D2L.Security.AuthTokenProvisioning.Tests.Unit.Default {
	
	internal sealed partial class AuthTokenProviderTests {

		private static JwtSecurityToken CheckSignatureAndGetToken( string signedToken, byte[] publicKey ) {
			using( RSACryptoServiceProvider rsaService = MakeCryptoServiceProvider() ) {
				rsaService.ImportCspBlob( publicKey );

				RsaSecurityToken rsaScurityToken = new RsaSecurityToken( rsaService );
				SecurityKey securityKey = rsaScurityToken.SecurityKeys[0];

				TokenValidationParameters validationParameters = CreateTokenValidationParameters( securityKey );
				ISecurityTokenValidator tokenHandler = CreateTokenHandler();

				SecurityToken securityToken;
				ClaimsPrincipal principal = tokenHandler.ValidateToken( signedToken, validationParameters, out securityToken );

				return (JwtSecurityToken)securityToken;
			}
		}

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
