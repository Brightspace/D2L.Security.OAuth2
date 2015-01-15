using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using D2L.Security.AuthTokenValidation.PublicKeys;
using D2L.Security.AuthTokenValidation.PublicKeys.Default;
using D2L.Security.AuthTokenValidation.Tests.Utilities;
using D2L.Security.AuthTokenValidation.TokenValidation;
using D2L.Security.AuthTokenValidation.TokenValidation.Default;
using Moq;
using NUnit.Framework;

namespace D2L.Security.AuthTokenValidation.Tests.Integration.TokenValidation {

	[TestFixture]
	internal sealed class TokenValidationTests {

		private const string ISSUER = "https://api.d2l.com/auth";

		[Test]
		public void Valid_Success() {
			RSAParameters rsaParams = TestTokenProvider.CreateRSAParams();
			RSACryptoServiceProvider rsaService = new RSACryptoServiceProvider();
			rsaService.ImportParameters( rsaParams );

			RsaKeyIdentifierClause clause = new RsaKeyIdentifierClause( rsaService );

			RsaSecurityToken securityToken = new RsaSecurityToken( rsaService );

			SecurityKey key = clause.CreateKey();
			

			IPublicKey publicKey = new PublicKey( securityToken, ISSUER );
			Mock<IPublicKeyProvider> publicKeyProviderMock = new Mock<IPublicKeyProvider>();
			publicKeyProviderMock.Setup( x => x.Get() ).Returns( publicKey );

			SecurityTokenHandlerConfiguration tokenHandlerConfiguration =
				new SecurityTokenHandlerConfiguration();
			tokenHandlerConfiguration.CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None;
			tokenHandlerConfiguration.CertificateValidator = System.IdentityModel.Selectors.X509CertificateValidator.None;

			JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
			tokenHandler.Configuration = tokenHandlerConfiguration;


			IJWTValidator validator = new JWTValidator(
				publicKeyProviderMock.Object,
				tokenHandler
				);

			//string payload = "{}";
			string payload = "{\"client_id\":\"lores_manager_client\",\"scope\":\"https://api.brightspace.com/auth/lores.manage\",\"iss\":\"https://api.d2l.com/auth\",\"aud\":\"https://api.d2l.com/auth/resources\",\"exp\":1421356474,\"nbf\":1421352874}";
			string jwt = TestTokenProvider.MakeJwt( "RS256", "JWT", payload, rsaParams );

			IValidatedJWT validatedToken = validator.Validate( jwt );

			//X509AsymmetricSecurityKey key2 = new X509AsymmetricSecurityKey()
			
			//byte[] rawX5c = null;
			//System.Security.Cryptography.X509Certificates.X509Certificate2 certificate =
			//	new System.Security.Cryptography.X509Certificates.X509Certificate2( rawX5c );
			//X509SecurityToken securityToken = new X509SecurityToken( certificate );
			//IPublicKey publicKey = new PublicKey( securityToken, ISSUER );

			rsaService.Dispose();

			Assert.Inconclusive();
		}

		[Test]
		public void Expired_Failure() {
			Assert.Inconclusive();
		}

		[Test]
		public void InvalidAlgorithm_Failure() {
			Assert.Inconclusive();
		}

		[Test]
		public void InvalidTokenType_Failure() {
			Assert.Inconclusive();
		}

		[Test]
		public void InvalidIssuer_Failure() {
			Assert.Inconclusive();
		}

		[Test]
		public void NullToken_Failure() {
			Assert.Inconclusive();
		}

		[Test]
		public void EmptyToken_Failure() {
			Assert.Inconclusive();
		}

		[Test]
		public void NonBase64Token_Failure() {
			Assert.Inconclusive();
		}

		[Test]
		public void MalformedJson_Failure() {
			Assert.Inconclusive();
		}
	}
}
