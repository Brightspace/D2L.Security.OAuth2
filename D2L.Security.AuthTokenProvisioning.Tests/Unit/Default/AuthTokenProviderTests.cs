using System;
using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.ServiceModel.Security;
using System.Text;
using System.Threading.Tasks;
using D2L.Security.AuthTokenProvisioning.Default;
using D2L.Security.AuthTokenProvisioning.Invocation;
using Moq;
using NUnit.Framework;

namespace D2L.Security.AuthTokenProvisioning.Tests.Unit.Default {
	
	[TestFixture]
	internal sealed class AuthTokenProviderTests {

		// since the provider tries to deserialize the assertion grant response, 
		// we need one containing valid JSON
		private const string ASSERTION_GRANT_RESPONSE = "{\"access_token\":\"bogus\",\"expires_in\":3600}";

		private static readonly ProvisioningParameters PROVISIONING_PARAMS = new ProvisioningParameters(
			"some_client_id",
			"some_client_secret",
			new string[] { "https://api.brightspace.com/auth/lores.manage" },
			"some_tenant_id",
			"some_tenant_url"
			);

		[Test]
		public void b() {
			byte[] privateKey;
			byte[] publicKey;

			MakeKeyPair( out privateKey, out publicKey );

			string signedToken = CreateAndSignToken( privateKey );
			JwtSecurityToken signatureCheckedToken = CheckSignatureAndGetToken( signedToken, publicKey );
		}

		private static string CreateAndSignToken( byte[] signingKey ) {
			InvocationParameters actualInvocationParams = null;
			Mock<IAuthServiceInvoker> invokerMock = new Mock<IAuthServiceInvoker>();
			invokerMock
				.Setup( x => x.ProvisionAccessToken( It.IsAny<InvocationParameters>() ) )
				.Callback<InvocationParameters>( x => actualInvocationParams = x )
				.Returns( ASSERTION_GRANT_RESPONSE );

			using( RSACryptoServiceProvider rsaService = new RSACryptoServiceProvider( 2048 ) ) {
				rsaService.PersistKeyInCsp = false;
				rsaService.ImportCspBlob( signingKey );

				RsaSecurityKey rsaSecurityKey = new RsaSecurityKey( rsaService );
				SigningCredentials signingCredentials =
					new SigningCredentials( rsaSecurityKey, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest );

				IAuthTokenProvider provider = new AuthTokenProvider(
					signingCredentials,
					invokerMock.Object
					);


				provider.ProvisionAccessToken( PROVISIONING_PARAMS );

				return actualInvocationParams.Assertion;
			}
		}

		private static JwtSecurityToken CheckSignatureAndGetToken( string signedToken, byte[] publicKey ) {
			using( RSACryptoServiceProvider rsaService = new RSACryptoServiceProvider( 2048 ) ) {
				rsaService.PersistKeyInCsp = false;
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

		private static void MakeKeyPair( out byte[] privateKey, out byte[] publicKey ) {
			using( RSACryptoServiceProvider rsaService = new RSACryptoServiceProvider( 2048 ) ) {
				rsaService.PersistKeyInCsp = false;

				privateKey = rsaService.ExportCspBlob( true );
				publicKey = rsaService.ExportCspBlob( false );
			}
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
			validationParameters.IssuerSigningKey = securityKey;
			validationParameters.ValidateIssuerSigningKey = true;
			validationParameters.ValidateLifetime = false;
			validationParameters.ValidateIssuer = false;
			validationParameters.ValidateAudience = false;
			validationParameters.ValidateActor = false;
			
			return validationParameters;
		}
	}
}
