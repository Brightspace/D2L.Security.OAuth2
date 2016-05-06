using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using D2L.Services;
using D2L.Security.OAuth2.TestFrameworks;
using D2L.Security.OAuth2.Validation.Exceptions;
using HttpMock;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Keys.Default.Data {
	[TestFixture]
	public class JwksProviderTests {
		private const string GOOD_PATH = "/goodpath";
		private const string BAD_PATH = "/badpath";
		private const string HTML_PATH = "/html";
		private const string JWKS_PATH = "/.well-known/jwks";

		private static Guid GOOD_JWK_ID = Guid.NewGuid();
		private static string GOOD_JWK = @"{""kid"":""" + GOOD_JWK_ID + @""",""kty"":""RSA"",""use"":""sig"",""n"":""piXmF9_L0UO4K5APzHqiOYl_KtVXAgPlVHhUopPztaW_JRh2k9MDeupIA1cAF9S_r5qRBWcA1QaP0nlGalw3jm_fSHvtUYYhwUhF9X6I19VRmv_BX9Ne2budt5dafI9DbNs2Ltq0X_yfM1dUL81vaR0rz7jYaQ5bF2CRQHVCcIhWkik85PG5c1yK__As842WqogBpW8-zsEoB6s53FNpDG37_HsZAAngATmTY1At4O7jC6p-c0KVPDf25oLVMOWQubyVgCE9FlsVxprHWqsXenlnHEmhZfEbFB_5KB6hj2yV77jhvLRslNvyKflFBs6AGCiczNDzmoXH2GV3FAVLFQ"",""e"":""AQAB""}";
		private static string GOOD_JSON = @"{""keys"": [" + GOOD_JWK + "]}";
		private static string HTML = "<html><body><p>This isn't JSON eh</p></body></html>";


		private IHttpServer m_jwksServer;
		private string m_host;
		
		[TestFixtureSetUp]
		public void TestFixtureSetUp() {
			m_jwksServer = HttpMockFactory.Create( out m_host );
			
			m_jwksServer.Stub(
				x => x.Get( GOOD_PATH + JWKS_PATH )
			).Return( GOOD_JSON ).OK();
			
			m_jwksServer.Stub(
				x => x.Get( BAD_PATH )
			).Return( GOOD_JSON ).WithStatus( HttpStatusCode.InternalServerError );

			m_jwksServer.Stub(
				x => x.Get( HTML_PATH + JWKS_PATH )
			).Return( HTML ).WithStatus( HttpStatusCode.OK );
		}

		[TestFixtureTearDown]
		public void TestFixtureTearDown() {
			m_jwksServer.Dispose();
		}

		[Test]
		public async Task SuccessCase() {
			IJwksProvider publicKeyProvider = new JwksProvider(
				new HttpClient(),
				new Uri( m_host + GOOD_PATH )
			);

			JsonWebKeySet jwks = await publicKeyProvider
				.RequestJwksAsync()
				.SafeAsync();
			JsonWebKey jwk;

			Assert.IsNotNull( jwks );
			Assert.IsTrue( jwks.TryGetKey( GOOD_JWK_ID, out jwk ) );
		}

		[Test]
		public void RequestJwksAsync_HTML_Throws() {
			IJwksProvider publicKeyProvider = new JwksProvider(
				new HttpClient(),
				new Uri( m_host + HTML_PATH )
			);

			var e = Assert.Throws<PublicKeyLookupFailureException>( () =>
				publicKeyProvider
					.RequestJwksAsync()
					.SafeWait()
				);

			StringAssert.Contains( "<body>", e.Message );
		}

		[Test]
		[ExpectedException( typeof( PublicKeyLookupFailureException ) )]
		public async Task RequestJwksAsync_404_Throws() {
			IJwksProvider publicKeyProvider = new JwksProvider(
				new HttpClient(),
				new Uri( m_host + BAD_PATH )
			);

			JsonWebKeySet jwks = await publicKeyProvider
				.RequestJwksAsync()
				.SafeAsync();
		}

		[Test]
		[ExpectedException( typeof( PublicKeyLookupFailureException ) )]
		public async Task RequestJwksAsync_CantReachServer_Throws() {
			IJwksProvider publicKeyProvider = new JwksProvider(
				new HttpClient(),
				new Uri( "http://foo.bar.fakesite.isurehopethisisneveravalidTLD" )
			);

			JsonWebKeySet jwks = await publicKeyProvider
				.RequestJwksAsync()
				.SafeAsync();
		}
	}
}
