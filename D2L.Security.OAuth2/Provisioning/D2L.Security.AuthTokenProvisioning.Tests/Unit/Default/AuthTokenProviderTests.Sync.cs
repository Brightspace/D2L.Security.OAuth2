using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;
using System.ServiceModel.Security;
using D2L.Security.AuthTokenProvisioning.Default;
using D2L.Security.AuthTokenProvisioning.Invocation;
using Moq;
using NUnit.Framework;

namespace D2L.Security.AuthTokenProvisioning.Tests.Unit.Default {
	
	[TestFixture]
	internal sealed partial class AuthTokenProviderTests {

		// since the provider tries to deserialize the assertion grant response, 
		// we need one containing valid JSON
		private const string ASSERTION_GRANT_RESPONSE = "{\"access_token\":\"bogus\",\"expires_in\":3600}";

		private static readonly ProvisioningParameters PROVISIONING_PARAMS = new ProvisioningParameters(
			"some_client_id",
			"some_client_secret",
			new string[] { "https://api.brightspace.com/auth/lores.manage" },
			"some_tenant_id",
			"some_tenant_url"
			) {
			UserId = "some_user_id"
		};

		[Test]
		public void ProvisionAccessToken_AssertionTokenIsSigned() {
			byte[] privateKey;
			byte[] publicKey;
			MakeKeyPair( out privateKey, out publicKey );

			InvocationParameters actualInvocationParams = null;
			Mock<IAuthServiceInvoker> invokerMock = new Mock<IAuthServiceInvoker>();
			invokerMock
				.Setup( x => x.ProvisionAccessToken( It.IsAny<InvocationParameters>() ) )
				.Callback<InvocationParameters>( x => actualInvocationParams = x )
				.Returns( ASSERTION_GRANT_RESPONSE );

			SignToken( invokerMock.Object, privateKey );
			string signedToken = actualInvocationParams.Assertion;

			JwtSecurityToken signatureCheckedToken = CheckSignatureAndGetToken( signedToken, publicKey );
			Assert.AreEqual( PROVISIONING_PARAMS.UserId, signatureCheckedToken.Subject );
		}

		private static void SignToken( IAuthServiceInvoker serviceInvoker, byte[] signingKey ) {

			using( RSACryptoServiceProvider rsaService = MakeCryptoServiceProvider() ) {
				rsaService.ImportCspBlob( signingKey );

				RsaSecurityKey rsaSecurityKey = new RsaSecurityKey( rsaService );
				SigningCredentials signingCredentials =	new SigningCredentials( 
					rsaSecurityKey, 
					SecurityAlgorithms.RsaSha256Signature, 
					SecurityAlgorithms.Sha256Digest 
					);

				IAuthTokenProvider provider = new AuthTokenProvider(
					signingCredentials,
					serviceInvoker
					);

				provider.ProvisionAccessToken( PROVISIONING_PARAMS );
			}
		}

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

		private static void MakeKeyPair( out byte[] privateKey, out byte[] publicKey ) {
			using( RSACryptoServiceProvider rsaService = MakeCryptoServiceProvider() ) {
				privateKey = rsaService.ExportCspBlob( true );
				publicKey = rsaService.ExportCspBlob( false );
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
