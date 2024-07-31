using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Keys;
using D2L.Security.OAuth2.TestFramework;
using D2L.Security.OAuth2.Validation.Exceptions;
using NUnit.Framework;
using RichardSzalay.MockHttp;

namespace D2L.Security.OAuth2.Validation.AccessTokens {
	internal sealed partial class AccessTokenValidatorTests {
		[TestFixture]
		internal sealed class EcDsa {
			private AuthServiceMock m_authService;
			private IAccessTokenValidator m_accessTokenValidator;

			[OneTimeSetUp]
			public void TestFixtureSetUp() {
				m_authService = new AuthServiceMock( AuthServiceMock.KeyType.ECDSA_P256 );
				m_accessTokenValidator = AccessTokenValidatorFactory.CreateRemoteValidator(
					new HttpClient( m_authService.MockHandler ),
					new Uri( m_authService.Host, ".well-known/jwks" )
				);

				m_authService.SetupJwks().Wait();
			}

			[OneTimeTearDown]
			public void TestFixtureTearDown() {
				if( m_authService != null ) {
					m_authService.Dispose();
				}
			}

			[Test]
			public async Task ValidateAsync_GoodSignature_Succeeds() {
				const string SUBJECT = "123";
				string token = await m_authService
					.SignTokenBackdoor( new UnsignedToken(
						"fake issuer",
						"fake audience",
						new Dictionary<string, object> { { "sub", SUBJECT } },
						DateTime.UtcNow - TimeSpan.FromSeconds( 1 ),
						DateTime.UtcNow + TimeSpan.FromHours( 1 ) ) )
					.ConfigureAwait( false );

				IAccessToken accessToken = await m_accessTokenValidator
					.ValidateAsync( token )
					.ConfigureAwait( false );

				Assert.IsNotNull( accessToken );
				Assert.AreEqual( SUBJECT, accessToken.Claims.Single( c => c.Type == "sub" ).Value );
				Assert.IsFalse( accessToken.Claims.Any( c => c.Type == "fakeclaim" ) );
			}

			[Test]
			public async Task ValidateAsync_BadSignature_Fails() {
				string token = await m_authService
					.SignTokenBackdoor( new UnsignedToken(
						"fake issuer",
						"fake audience",
						new Dictionary<string, object>(),
						DateTime.UtcNow - TimeSpan.FromSeconds( 1 ),
						DateTime.UtcNow + TimeSpan.FromHours( 1 ) ) )
					.ConfigureAwait( false );

				token += "abcd";

				Assert.Throws<ValidationException>( () =>
					m_accessTokenValidator
						.ValidateAsync( token )
						.ConfigureAwait( false )
						.GetAwaiter()
						.GetResult()
					);
			}

			[Test]
			public void ValidateAsync_KeyIdNotInAuthService_Fails() {
				// This JWT has a keyId that doesn't match the one in the auth service
				string jwtWithBadKeyId = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAwMCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.dUQ2bB3anqRmI-wnC4bulmnwo7wAdrvXo3hn3Dp0tuUl01dy2FhsJESJ9BZ2BeykrLRv2EgdbTW3BCBpBqLbrKQaG_XuGX5MrtXFwHE7i9wWmDsetlJn_cvsZlhPg-voI2iGqT-gpiE9GfWcXjTPUCxAbz6Pqepi0-JDS9uTrCg";

				var e = Assert.Throws<PublicKeyNotFoundException>( () => {
					var response = m_accessTokenValidator
						.ValidateAsync( jwtWithBadKeyId )
						.ConfigureAwait( false ).GetAwaiter().GetResult();
				} );

				StringAssert.Contains( "00000000-0000-0000-0000-000000000000", e.Message );
				StringAssert.Contains( m_authService.Host.AbsoluteUri, e.Message );
			}

			private static readonly TestCaseData[] WebCrypto_TestCases = {
				new TestCaseData(
					"{\"crv\":\"P-256\",\"ext\":true,\"key_ops\":[\"verify\"],\"kty\":\"EC\",\"x\":\"l11cYO8NXZAHiXJfXYkBHesiUEUN5nrjPCL5Rr5tw2M\",\"y\":\"ooSg8_JyPyH7fIA5MGTy99aVwSy7PYwogW32WkVOb-E\",\"kid\":\"c9f4fe54-417e-4279-8676-fc3c605c4720\",\"use\":\"sig\"}",
					"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImM5ZjRmZTU0LTQxN2UtNDI3OS04Njc2LWZjM2M2MDVjNDcyMCJ9.eyJleHAiOjE0MzM4NzE1MjUsImlzcyI6ImZha2UgaXNzdWVyIn0.yA4WNemRpUreSh9qgMh_ePGqhgn328ghJ_HG7WOBKQV98eFNm3FIvweoiSzHvl49Z6YTdV4Up7NDD7UcZ-52cw"
					).SetName( "WebCrypto ES256" ),
				new TestCaseData(
					"{\"crv\":\"P-384\",\"ext\":true,\"key_ops\":[\"verify\"],\"kty\":\"EC\",\"x\":\"129X-ELqKL2uiGVCbaJXzaFTgCVZyw4DT20EdPnyBMxiImUyocnOIrjFx3pJLbak\",\"y\":\"3q6ETaKHVe8Jd4fxZNnx3_h-UAcquqoqGTYZz_drxfEELXqaqar2qbdDKYmE_c3g\",\"kid\":\"308e6c00-389e-44a9-a567-21b8391f61ff\",\"use\":\"sig\"}",
					"eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6IjMwOGU2YzAwLTM4OWUtNDRhOS1hNTY3LTIxYjgzOTFmNjFmZiJ9.eyJleHAiOjE0MzM4NzE4NjksImlzcyI6ImZha2UgaXNzdWVyIn0.TsS1fXqgq5S2lpjO-Tz5w6ZAKqNFuQ6PufvXRN2NRY2DEsQ3iUXdEcAzcMXNqVehkZ-NwUxdIvDqwKTGLYQYVhjBxkdnwm1T5VKG2v1BYFeDQ91sgBlVhHFzvFty5wCI"
					).SetName( "WebCrypto ES384" ),
				new TestCaseData(
					"{\"crv\":\"P-521\",\"ext\":true,\"key_ops\":[\"verify\"],\"kty\":\"EC\",\"x\":\"AMZPDU8qq2oasB8of22nS5WY0_MTttxlwZbMWpcEW5Ne0ep9IDQuBij4HW8zUNOw4ExIfXmjarqli8efEd6UK8KI\",\"y\":\"AQMBVhBneJcdqIiX1clSb3TBVlUk-7iP04XwThD6J66tjcv66ZuXswAzluS36oIfaKDeOy2bmZOcSD0ykgKupXC5\",\"kid\":\"ace3e887-f024-4277-97a5-155dee721dd6\",\"use\":\"sig\"}",
					"eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6ImFjZTNlODg3LWYwMjQtNDI3Ny05N2E1LTE1NWRlZTcyMWRkNiJ9.eyJleHAiOjE0MzM4NzIwMTMsImlzcyI6ImZha2UgaXNzdWVyIn0.AFKapY_5gq60n8NZ_C2iOQFov7sXgcMyDzCrnGsbvE7OlSBKbgj95aZ7GtdSdbw6joK2jjWJio8IgKNB9o11GdMTADfLUsv9oAJvmIApsmsPBAIe1vH8oeHYiDMBEz9OQcwS5eL-r1iO2v7oxzl9zZb1rA5kzBqS93ARCPKbjgcr602r"
					).SetName( "WebCrypto ES512" )
			};

			[Test, TestCaseSource( "WebCrypto_TestCases" )]
			public void ValidateAsync_GoodSignature_Succeeds_WebCrypto( string jwk, string token ) {
				var mockHandler = new MockHttpMessageHandler();

				mockHandler
					.When( "http://localhost/.well-known/jwks" )
					.Respond( "application/json", @"{""keys"":[" + jwk + "]}" );

				// We expect these to be expired because they are static
				// The rest of the validation should have otherwise proceeded swimmingly
				Assert.Throws<ExpiredTokenException>( () =>
					AccessTokenValidatorFactory
						.CreateRemoteValidator( new HttpClient( mockHandler ), new Uri( "http://localhost/.well-known/jwks" ) )
						.ValidateAsync( token )
						.ConfigureAwait( false ).GetAwaiter().GetResult()
				);
			}
		}
	}
}
