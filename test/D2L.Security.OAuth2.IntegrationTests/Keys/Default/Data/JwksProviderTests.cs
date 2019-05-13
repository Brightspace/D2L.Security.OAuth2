using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using D2L.Security.OAuth2.TestFrameworks;
using D2L.Security.OAuth2.Validation.Exceptions;
using D2L.Services;
using HttpMock;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Keys.Default.Data {
	[TestFixture]
	public class JwksProviderTests {
		private const string GOOD_PATH = "/goodpath";
		private const string BAD_PATH = "/badpath";
		private const string HTML_PATH = "/html";
		private const string JWKS_PATH = "/.well-known/jwks";
		private const string GOOD_JWK_ID_STRING = "NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg";

		private static string GOOD_JWK_ID = Guid.NewGuid().ToString();
		private static readonly string GOOD_JWK = @"{""kid"":""" + GOOD_JWK_ID + @""",""kty"":""RSA"",""use"":""sig"",""n"":""piXmF9_L0UO4K5APzHqiOYl_KtVXAgPlVHhUopPztaW_JRh2k9MDeupIA1cAF9S_r5qRBWcA1QaP0nlGalw3jm_fSHvtUYYhwUhF9X6I19VRmv_BX9Ne2budt5dafI9DbNs2Ltq0X_yfM1dUL81vaR0rz7jYaQ5bF2CRQHVCcIhWkik85PG5c1yK__As842WqogBpW8-zsEoB6s53FNpDG37_HsZAAngATmTY1At4O7jC6p-c0KVPDf25oLVMOWQubyVgCE9FlsVxprHWqsXenlnHEmhZfEbFB_5KB6hj2yV77jhvLRslNvyKflFBs6AGCiczNDzmoXH2GV3FAVLFQ"",""e"":""AQAB""}";
		private static readonly string GOOD_JWK_STRING = @"{""kid"":""" + GOOD_JWK_ID_STRING + @""",""kty"":""RSA"",""use"":""sig"",""n"":""piXmF9_L0UO4K5APzHqiOYl_KtVXAgPlVHhUopPztaW_JRh2k9MDeupIA1cAF9S_r5qRBWcA1QaP0nlGalw3jm_fSHvtUYYhwUhF9X6I19VRmv_BX9Ne2budt5dafI9DbNs2Ltq0X_yfM1dUL81vaR0rz7jYaQ5bF2CRQHVCcIhWkik85PG5c1yK__As842WqogBpW8-zsEoB6s53FNpDG37_HsZAAngATmTY1At4O7jC6p-c0KVPDf25oLVMOWQubyVgCE9FlsVxprHWqsXenlnHEmhZfEbFB_5KB6hj2yV77jhvLRslNvyKflFBs6AGCiczNDzmoXH2GV3FAVLFQ"",""e"":""AQAB""}";
		private static readonly string GOOD_JSON = @"{""keys"": [" + GOOD_JWK + "," + GOOD_JWK_STRING + "]}";
		private static readonly string HTML = "<html><body><p>This isn't JSON eh</p></body></html>";
		private static readonly string GOOD_JWK_PATH = GOOD_PATH + "/jwk/" + GOOD_JWK_ID;
		private static readonly string GOOD_JWK_STRING_PATH = GOOD_PATH + "/jwk/" + GOOD_JWK_ID_STRING;

		private IHttpServer SetupJwkServer(
			out string host,
			bool hasJwk = true,
			HttpStatusCode jwkStatusCode = HttpStatusCode.OK
		) {
			IHttpServer jwksServer = HttpMockFactory.Create( out host );

			jwksServer.Stub(
				x => x.Get( GOOD_PATH + JWKS_PATH )
			).Return( GOOD_JSON ).OK();

			jwksServer.Stub(
				x => x.Get( BAD_PATH )
			).Return( GOOD_JSON ).WithStatus( HttpStatusCode.InternalServerError );

			jwksServer.Stub(
				x => x.Get( HTML_PATH + JWKS_PATH )
			).Return( HTML ).WithStatus( HttpStatusCode.OK );

			jwksServer
				.Stub( x => x.Get( GOOD_JWK_PATH ) )
				.Return( hasJwk ? GOOD_JWK : "" )
				.WithStatus( jwkStatusCode );

			jwksServer
				.Stub( x => x.Get( GOOD_JWK_STRING_PATH ) )
				.Return( hasJwk ? GOOD_JWK_STRING : "" )
				.WithStatus( jwkStatusCode );

			return jwksServer;
		}

		[Test]
		public async Task SuccessCase() {
			using( SetupJwkServer( out string host ) )
			using( HttpClient httpClient = new HttpClient() ) {
				IJwksProvider publicKeyProvider = new JwksProvider(
					httpClient,
					new Uri( host + GOOD_PATH )
				);

				JsonWebKeySet jwks = await publicKeyProvider
					.RequestJwksAsync()
					.SafeAsync();

				Assert.IsNotNull( jwks );
				Assert.IsTrue( jwks.TryGetKey( GOOD_JWK_ID, out JsonWebKey jwk ) );
				Assert.IsTrue( jwks.TryGetKey( GOOD_JWK_ID_STRING, out JsonWebKey jwkString ) );
			}
		}

		[Test]
		public void RequestJwksAsync_HTML_Throws() {
			using( SetupJwkServer( out string host ) )
			using( HttpClient httpClient = new HttpClient() ) {
				IJwksProvider publicKeyProvider = new JwksProvider(
					httpClient,
					new Uri( host + HTML_PATH )
				);

				var e = Assert.Throws<PublicKeyLookupFailureException>( () =>
					publicKeyProvider
						.RequestJwksAsync()
						.SafeWait()
					);

				StringAssert.Contains( "<body>", e.Message );
			}
		}

		[Test]
		public void RequestJwksAsync_404_Throws() {
			using( SetupJwkServer( out string host ) )
			using( HttpClient httpClient = new HttpClient() ) {
				IJwksProvider publicKeyProvider = new JwksProvider(
					httpClient,
					new Uri( host + BAD_PATH )
				);

				Assert.ThrowsAsync<PublicKeyLookupFailureException>( async () => {
					JsonWebKeySet jwks = await publicKeyProvider
						.RequestJwksAsync()
						.SafeAsync();
				} );
			}
		}

		[Test]
		public void RequestJwksAsync_CantReachServer_Throws() {
			using( SetupJwkServer( out string host ) )
			using( HttpClient httpClient = new HttpClient() ) {
				IJwksProvider publicKeyProvider = new JwksProvider(
					httpClient,
					new Uri( "http://foo.bar.fakesite.isurehopethisisneveravalidTLD" )
				);

				Assert.ThrowsAsync<PublicKeyLookupFailureException>( async () => {
					JsonWebKeySet jwks = await publicKeyProvider
					.RequestJwksAsync()
					.SafeAsync();
				} );
			}
		}

		[Test]
		public async Task RequestJwkAsync_Success() {
			using( SetupJwkServer( out string host, hasJwk: true, jwkStatusCode: HttpStatusCode.OK ) )
			using( HttpClient httpClient = new HttpClient() ) {
				IJwksProvider jwksProvider = new JwksProvider(
					httpClient,
					new Uri( host + GOOD_PATH )
				);

				JsonWebKeySet jwks = await jwksProvider
					.RequestJwkAsync( GOOD_JWK_ID )
					.SafeAsync();
				Assert.IsNotNull( jwks );

				//jwksServer.AssertWasCalled( x => x.Get( GOOD_JWK_PATH ) );
				//jwksServer.AssertWasNotCalled( x => x.Get( GOOD_PATH + JWKS_PATH ) );

				Assert.IsTrue( jwks.TryGetKey( GOOD_JWK_ID, out JsonWebKey jwk ) );
				Assert.AreEqual( GOOD_JWK_ID, jwk.Id );
			}
		}

		[Test]
		public async Task RequestJwkAsync_StringKeyId_Success() {
			using( SetupJwkServer( out string host, hasJwk: true, jwkStatusCode: HttpStatusCode.OK ) )
			using( HttpClient httpClient = new HttpClient() ) {
				IJwksProvider jwksProvider = new JwksProvider(
					httpClient,
					new Uri( host + GOOD_PATH )
				);

				JsonWebKeySet jwks = await jwksProvider
					.RequestJwkAsync( GOOD_JWK_ID_STRING )
					.SafeAsync();
				Assert.IsNotNull( jwks );

				//jwksServer.AssertWasCalled( x => x.Get( GOOD_JWK_PATH ) );
				//jwksServer.AssertWasNotCalled( x => x.Get( GOOD_PATH + JWKS_PATH ) );

				Assert.IsTrue( jwks.TryGetKey( GOOD_JWK_ID_STRING, out JsonWebKey jwk ) );
				Assert.AreEqual( GOOD_JWK_ID_STRING, jwk.Id );
			}
		}

		[Test]
		public async Task RequestJwkAsync_StringKeyId_InvalidKeyId_Fallback_DoesNotReturnKey() {
			using( SetupJwkServer( out string host, hasJwk: true, jwkStatusCode: HttpStatusCode.OK ) )
			using( HttpClient httpClient = new HttpClient() ) {
				IJwksProvider jwksProvider = new JwksProvider(
					httpClient,
					new Uri( host + GOOD_PATH )
				);

				JsonWebKeySet jwks = await jwksProvider
					.RequestJwkAsync( "NJVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg" )
					.SafeAsync();
				Assert.IsNotNull( jwks );

				//jwksServer.AssertWasCalled( x => x.Get( GOOD_JWK_PATH ) );
				//jwksServer.AssertWasNotCalled( x => x.Get( GOOD_PATH + JWKS_PATH ) );

				Assert.IsFalse( jwks.TryGetKey( "NJVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg", out JsonWebKey jwk ) );
			}
		}

		[Test]
		public async Task RequestJwkAsync_404_Fallback_Success() {
			using( SetupJwkServer( out string host, hasJwk: false, jwkStatusCode: HttpStatusCode.NotFound ) )
			using( HttpClient httpClient = new HttpClient() ) {
				IJwksProvider jwksProvider = new JwksProvider(
					httpClient,
					new Uri( host + GOOD_PATH )
				);

				JsonWebKeySet jwks = await jwksProvider
					.RequestJwkAsync( GOOD_JWK_ID )
					.SafeAsync();
				Assert.IsNotNull( jwks );

				//jwksServer.AssertWasCalled( x => x.Get( GOOD_JWK_PATH ) );
				//jwksServer.AssertWasCalled( x => x.Get( GOOD_PATH + JWKS_PATH ) );

				Assert.IsTrue( jwks.TryGetKey( GOOD_JWK_ID, out JsonWebKey jwk ) );
				Assert.AreEqual( GOOD_JWK_ID, jwk.Id );
			}
		}

		[Test]
		public async Task RequestJwkAsync_StringKeyId_404_Fallback_Success() {
			using( SetupJwkServer( out string host, hasJwk: false, jwkStatusCode: HttpStatusCode.NotFound ) )
			using( HttpClient httpClient = new HttpClient() ) {
				IJwksProvider jwksProvider = new JwksProvider(
					httpClient,
					new Uri( host + GOOD_PATH )
				);

				JsonWebKeySet jwks = await jwksProvider
					.RequestJwkAsync( GOOD_JWK_ID_STRING )
					.SafeAsync();
				Assert.IsNotNull( jwks );

				//jwksServer.AssertWasCalled( x => x.Get( GOOD_JWK_PATH ) );
				//jwksServer.AssertWasCalled( x => x.Get( GOOD_PATH + JWKS_PATH ) );

				Assert.IsTrue( jwks.TryGetKey( GOOD_JWK_ID_STRING, out JsonWebKey jwk ) );
				Assert.AreEqual( GOOD_JWK_ID_STRING, jwk.Id );
			}
		}

		[Test]
		public async Task RequestJwkAsync_500_Fallback_Success() {
			using( SetupJwkServer( out string host, hasJwk: false, jwkStatusCode: HttpStatusCode.InternalServerError ) )
			using( HttpClient httpClient = new HttpClient() ) {
				IJwksProvider jwksProvider = new JwksProvider(
					httpClient,
					new Uri( host + GOOD_PATH )
				);

				JsonWebKeySet jwks = await jwksProvider
					.RequestJwkAsync( GOOD_JWK_ID )
					.SafeAsync();
				Assert.IsNotNull( jwks );

				//jwksServer.AssertWasCalled( x => x.Get( GOOD_JWK_PATH ) );
				//jwksServer.AssertWasCalled( x => x.Get( GOOD_PATH + JWKS_PATH ) );

				Assert.IsTrue( jwks.TryGetKey( GOOD_JWK_ID, out JsonWebKey jwk ) );
				Assert.AreEqual( GOOD_JWK_ID, jwk.Id );
			}
		}

		[Test]
		public async Task RequestJwkAsync_StringKeyId_500_Fallback_Success() {
			using( SetupJwkServer( out string host, hasJwk: false, jwkStatusCode: HttpStatusCode.InternalServerError ) )
			using( HttpClient httpClient = new HttpClient() ) {
				IJwksProvider jwksProvider = new JwksProvider(
					httpClient,
					new Uri( host + GOOD_PATH )
				);

				JsonWebKeySet jwks = await jwksProvider
					.RequestJwkAsync( GOOD_JWK_ID_STRING )
					.SafeAsync();
				Assert.IsNotNull( jwks );

				//jwksServer.AssertWasCalled( x => x.Get( GOOD_JWK_PATH ) );
				//jwksServer.AssertWasCalled( x => x.Get( GOOD_PATH + JWKS_PATH ) );

				Assert.IsTrue( jwks.TryGetKey( GOOD_JWK_ID_STRING, out JsonWebKey jwk ) );
				Assert.AreEqual( GOOD_JWK_ID_STRING, jwk.Id );
			}
		}
	}
}
