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

		private static readonly DateTime UNIX_EPOCH_BEGINNING = new DateTime( 1970, 1, 1, 0, 0, 0, DateTimeKind.Utc );
		private const string ISSUER = "https://api.d2l.com/auth";
		private const string SCOPE = "https://api.brightspace.com/auth/lores.manage";
		private const string VALID_ALGORITHM = "RS256";
		private const string VALID_TOKEN_TYPE = "JWT";

		[Test]
		public void Valid_Success() {
			IValidatedJWT validatedToken;
			RSAParameters rsaParams = TestTokenProvider.CreateRSAParams();

			using( RSACryptoServiceProvider rsaService = new RSACryptoServiceProvider() ) {
				rsaService.ImportParameters( rsaParams );

				RsaKeyIdentifierClause clause = new RsaKeyIdentifierClause( rsaService );
				RsaSecurityToken securityToken = new RsaSecurityToken( rsaService );

				IPublicKey publicKey = new PublicKey( securityToken, ISSUER );
				Mock<IPublicKeyProvider> publicKeyProviderMock = new Mock<IPublicKeyProvider>();
				publicKeyProviderMock.Setup( x => x.Get() ).Returns( publicKey );

				ISecurityTokenValidator tokenHandler = JWTHelper.CreateTokenHandler();

				IJWTValidator validator = new JWTValidator(
					publicKeyProviderMock.Object,
					tokenHandler
					);

				string payload = MakePayload( ISSUER, SCOPE, TimeSpan.FromMinutes( 15 ) );
				string jwt = TestTokenProvider.MakeJwt( VALID_ALGORITHM, VALID_TOKEN_TYPE, payload, rsaParams );

				validatedToken = validator.Validate( jwt );
			}

			Assertions.ContainsScopeValue( validatedToken, SCOPE );
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

		private long GetSecondsRelativeToNow( TimeSpan delta ) {
			DateTime expiryTime = DateTime.UtcNow + delta;
			TimeSpan timeToExpireSinceUnixEpoch = expiryTime - UNIX_EPOCH_BEGINNING;
			long seconds = (long)timeToExpireSinceUnixEpoch.TotalSeconds;
			return seconds;
		}

		private string MakePayload( string issuer, string scope, TimeSpan expiryFromNow ) {
			long expiryInSeconds = GetSecondsRelativeToNow( expiryFromNow );

			StringBuilder payloadBuilder = new StringBuilder( "{\"client_id\":\"lores_manager_client\",\"scope\":\"" );
			payloadBuilder.Append( scope );
			payloadBuilder.Append( "\",\"iss\":\"" );
			payloadBuilder.Append( issuer );
			payloadBuilder.Append( "\",\"aud\":\"https://api.d2l.com/auth/resources\",\"exp\":" );
			payloadBuilder.Append( expiryInSeconds );
			payloadBuilder.Append( ",\"nbf\":1421352874}" );

			return payloadBuilder.ToString();
		}
	}
}
