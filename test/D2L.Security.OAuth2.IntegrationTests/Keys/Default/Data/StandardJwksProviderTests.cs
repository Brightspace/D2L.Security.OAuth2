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
	public class StandardJwksProviderTests {
		private const string GOOD_PATH = "/goodpath";
		private const string BAD_PATH = "/badpath";
		private const string HTML_PATH = "/html";
		private const string JWKS_PATH = "/.well-known/jwks";

		private static string GOOD_JWK_ID = Guid.NewGuid().ToString();
		private static readonly string GOOD_JWK = @"{""kid"":""" + GOOD_JWK_ID + @""",""kty"":""RSA"",""use"":""sig"",""n"":""piXmF9_L0UO4K5APzHqiOYl_KtVXAgPlVHhUopPztaW_JRh2k9MDeupIA1cAF9S_r5qRBWcA1QaP0nlGalw3jm_fSHvtUYYhwUhF9X6I19VRmv_BX9Ne2budt5dafI9DbNs2Ltq0X_yfM1dUL81vaR0rz7jYaQ5bF2CRQHVCcIhWkik85PG5c1yK__As842WqogBpW8-zsEoB6s53FNpDG37_HsZAAngATmTY1At4O7jC6p-c0KVPDf25oLVMOWQubyVgCE9FlsVxprHWqsXenlnHEmhZfEbFB_5KB6hj2yV77jhvLRslNvyKflFBs6AGCiczNDzmoXH2GV3FAVLFQ"",""e"":""AQAB""}";
		private static readonly string GOOD_JSON = @"{""keys"": [" + GOOD_JWK + "]}";
		private static readonly string HTML = "<html><body><p>This isn't JSON eh</p></body></html>";

		private IHttpServer SetupJwkServer(
			out string host
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

			return jwksServer;
		}

		[Test]
		public async Task SuccessCase() {
			using( SetupJwkServer( out string host ) )
			using( HttpClient httpClient = new HttpClient() ) {
				IJwksProvider publicKeyProvider = new D2LJwksProvider(
					httpClient,
					new Uri( host + GOOD_PATH )
				);

				JsonWebKeySet jwks = await publicKeyProvider
					.RequestJwksAsync()
					.SafeAsync();

				Assert.IsNotNull( jwks );
				Assert.IsTrue( jwks.TryGetKey( GOOD_JWK_ID, out JsonWebKey jwk ) );
			}
		}

		[Test]
		public void RequestJwksAsync_HTML_Throws() {
			using( SetupJwkServer( out string host ) )
			using( HttpClient httpClient = new HttpClient() ) {
				IJwksProvider publicKeyProvider = new D2LJwksProvider(
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
				IJwksProvider publicKeyProvider = new D2LJwksProvider(
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
				IJwksProvider publicKeyProvider = new D2LJwksProvider(
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
			using( SetupJwkServer( out string host ) )
			using( HttpClient httpClient = new HttpClient() ) {
				IJwksProvider jwksProvider = new D2LJwksProvider(
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
	}
}
