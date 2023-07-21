using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Utilities;
using D2L.Security.OAuth2.Validation.Exceptions;
using NUnit.Framework;
using RichardSzalay.MockHttp;

namespace D2L.Security.OAuth2.Keys.Default.Data {
	[TestFixture]
	public class JwksProviderTests {
		private const string GOOD_PATH = "/goodpath";
		private const string BAD_PATH = "/badpath";
		private const string HTML_PATH = "/html";
		private const string JWK_PATH = "/jwk/";
		private const string JWKS_PATH = "/.well-known/jwks";
		private const string GOOD_PATH_ADDITIONAL_OBJECT = "/additonalObject";
		private const string GOOD_PATH_ADDITIONAL_NUMBER = "/additionalNumber";

		private const string GOOD_JWK_ID_STRING = "NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg";
		private static string GOOD_JWK_ID = Guid.NewGuid().ToString();

		private static readonly string GOOD_JWK = @"{""kid"":""" + GOOD_JWK_ID + @""",""kty"":""RSA"",""use"":""sig"",""n"":""piXmF9_L0UO4K5APzHqiOYl_KtVXAgPlVHhUopPztaW_JRh2k9MDeupIA1cAF9S_r5qRBWcA1QaP0nlGalw3jm_fSHvtUYYhwUhF9X6I19VRmv_BX9Ne2budt5dafI9DbNs2Ltq0X_yfM1dUL81vaR0rz7jYaQ5bF2CRQHVCcIhWkik85PG5c1yK__As842WqogBpW8-zsEoB6s53FNpDG37_HsZAAngATmTY1At4O7jC6p-c0KVPDf25oLVMOWQubyVgCE9FlsVxprHWqsXenlnHEmhZfEbFB_5KB6hj2yV77jhvLRslNvyKflFBs6AGCiczNDzmoXH2GV3FAVLFQ"",""e"":""AQAB""}";
		private static readonly string GOOD_JWK_STRING = @"{""kid"":""" + GOOD_JWK_ID_STRING + @""",""kty"":""RSA"",""use"":""sig"",""n"":""piXmF9_L0UO4K5APzHqiOYl_KtVXAgPlVHhUopPztaW_JRh2k9MDeupIA1cAF9S_r5qRBWcA1QaP0nlGalw3jm_fSHvtUYYhwUhF9X6I19VRmv_BX9Ne2budt5dafI9DbNs2Ltq0X_yfM1dUL81vaR0rz7jYaQ5bF2CRQHVCcIhWkik85PG5c1yK__As842WqogBpW8-zsEoB6s53FNpDG37_HsZAAngATmTY1At4O7jC6p-c0KVPDf25oLVMOWQubyVgCE9FlsVxprHWqsXenlnHEmhZfEbFB_5KB6hj2yV77jhvLRslNvyKflFBs6AGCiczNDzmoXH2GV3FAVLFQ"",""e"":""AQAB""}";
		private static readonly string GOOD_JSON = @"{""keys"": [" + GOOD_JWK + "," + GOOD_JWK_STRING + "]}";
		private static readonly string GOOD_JSON_ADDITIONAL_OBJECT = @"{""additionalData"":{},""keys"": [" + GOOD_JWK + "," + GOOD_JWK_STRING + "]}";
		private static readonly string GOOD_JSON_ADDITIONAL_NUMBER = @"{""foo"":3,""keys"": [" + GOOD_JWK + "," + GOOD_JWK_STRING + "]}";
		private static readonly string HTML = "<html><body><p>This isn't JSON eh</p></body></html>";

		private HttpMessageHandler SetupJwkServer(
			out string host,
			bool hasJwk = true,
			HttpStatusCode jwkStatusCode = HttpStatusCode.OK
		) {
			MockHttpMessageHandler handler = new MockHttpMessageHandler();
			host = "http://localhost";

			handler
				.When( HttpMethod.Get, $"{ host }{ GOOD_PATH }{ JWKS_PATH }" )
				.Respond( "application/json", GOOD_JSON );

			handler
				.When( HttpMethod.Get, $"{ host }{ GOOD_PATH_ADDITIONAL_OBJECT }{ JWKS_PATH }" )
				.Respond( "application/json", GOOD_JSON_ADDITIONAL_OBJECT);

			handler
				.When( HttpMethod.Get, $"{ host }{ GOOD_PATH_ADDITIONAL_NUMBER }{ JWKS_PATH }" )
				.Respond( "application/json", GOOD_JSON_ADDITIONAL_NUMBER );

			handler
				.When( HttpMethod.Get, $"{ host }{ BAD_PATH }" )
				.Respond( HttpStatusCode.InternalServerError, "application/json", GOOD_JSON );

			handler
				.When( HttpMethod.Get, $"{ host }{ HTML_PATH }" )
				.Respond( "text/html", HTML );

			handler
				.When( HttpMethod.Get, $"{ host }{ GOOD_PATH }{ JWK_PATH }{ GOOD_JWK_ID }" )
				.Respond( jwkStatusCode, "application/json", hasJwk ? GOOD_JWK : "" );

			handler
				.When( HttpMethod.Get, $"{ host }{ GOOD_PATH }{ JWK_PATH }{ GOOD_JWK_ID_STRING }" )
				.Respond( jwkStatusCode, "application/json", hasJwk ? GOOD_JWK_STRING : "" );

			return handler;
		}

		[TestCase( GOOD_PATH )]
		[TestCase( GOOD_PATH_ADDITIONAL_OBJECT )]
		[TestCase( GOOD_PATH_ADDITIONAL_NUMBER )]
		public async Task RequestJwksAsync_SuccessCase( string goodPath ) {
			using( var handler = SetupJwkServer( out string host ) )
			using( HttpClient httpClient = new HttpClient( handler ) ) {
				IJwksProvider publicKeyProvider = new JwksProvider(
					httpClient,
					jwksEndpoint: new Uri( host + goodPath + JWKS_PATH ),
					jwkEndpoint: null
				);

				JsonWebKeySet jwks = await publicKeyProvider
					.RequestJwksAsync()
					.ConfigureAwait( false );

				Assert.IsNotNull( jwks );
				Assert.IsTrue( jwks.TryGetKey( GOOD_JWK_ID, out JsonWebKey jwk ) );
				Assert.IsTrue( jwks.TryGetKey( GOOD_JWK_ID_STRING, out JsonWebKey jwkString ) );
			}
		}

		[Test]
		public void RequestJwksAsync_HTML_Throws() {
			using( var handler = SetupJwkServer( out string host ) )
			using( HttpClient httpClient = new HttpClient( handler ) ) {
				IJwksProvider publicKeyProvider = new JwksProvider(
					httpClient,
					jwksEndpoint: new Uri( host + HTML_PATH ),
					jwkEndpoint: null
				);

				var e = Assert.Throws<PublicKeyLookupFailureException>( () =>
					publicKeyProvider
						.RequestJwksAsync()
						.ConfigureAwait( false ).GetAwaiter().GetResult()
					);

				StringAssert.Contains( "<body>", e.Message );
			}
		}

		[Test]
		public void RequestJwksAsync_404_Throws() {
			using( var handler = SetupJwkServer( out string host ) )
			using( HttpClient httpClient = new HttpClient( handler ) ) {
				IJwksProvider publicKeyProvider = new JwksProvider(
					httpClient,
					jwksEndpoint: new Uri( host + BAD_PATH ),
					jwkEndpoint: null
				);

				Assert.ThrowsAsync<PublicKeyLookupFailureException>( async () => {
					JsonWebKeySet jwks = await publicKeyProvider
						.RequestJwksAsync()
						.ConfigureAwait( false );
				} );
			}
		}

		[Test]
		public void RequestJwksAsync_CantReachServer_Throws() {
			using( var handler = SetupJwkServer( out string host ) )
			using( HttpClient httpClient = new HttpClient( handler ) ) {
				IJwksProvider publicKeyProvider = new JwksProvider(
					httpClient,
					jwksEndpoint: new Uri( "http://foo.bar.fakesite.isurehopethisisneveravalidTLD" ),
					jwkEndpoint: null
				);

				Assert.ThrowsAsync<PublicKeyLookupFailureException>( async () => {
					JsonWebKeySet jwks = await publicKeyProvider
					.RequestJwksAsync()
					.ConfigureAwait( false );
				} );
			}
		}

		[Test]
		public async Task RequestJwkAsync_Success() {
			using( var handler = SetupJwkServer( out string host, hasJwk: true, jwkStatusCode: HttpStatusCode.OK ) )
			using( HttpClient httpClient = new HttpClient( handler ) ) {
				IJwksProvider jwksProvider = new JwksProvider(
					httpClient,
					jwksEndpoint: new Uri( host + GOOD_PATH + JWKS_PATH ),
					jwkEndpoint: new Uri( host + GOOD_PATH + JWK_PATH )
				);

				JsonWebKeySet jwks = await jwksProvider
					.RequestJwkAsync( GOOD_JWK_ID )
					.ConfigureAwait( false );
				Assert.IsNotNull( jwks );

				//jwksServer.AssertWasCalled( x => x.Get( GOOD_JWK_PATH ) );
				//jwksServer.AssertWasNotCalled( x => x.Get( GOOD_PATH + JWKS_PATH ) );

				Assert.IsTrue( jwks.TryGetKey( GOOD_JWK_ID, out JsonWebKey jwk ) );
				Assert.AreEqual( GOOD_JWK_ID, jwk.Id );
			}
		}

		[Test]
		public async Task RequestJwkAsync_NullJwkEndpoint_Fallback_Success() {
			using( var handler = SetupJwkServer( out string host, hasJwk: true, jwkStatusCode: HttpStatusCode.OK ) )
			using( HttpClient httpClient = new HttpClient( handler ) ) {
				IJwksProvider jwksProvider = new JwksProvider(
					httpClient,
					jwksEndpoint: new Uri( host + GOOD_PATH + JWKS_PATH ),
					jwkEndpoint: null
				);

				JsonWebKeySet jwks = await jwksProvider
					.RequestJwkAsync( GOOD_JWK_ID )
					.ConfigureAwait( false );
				Assert.IsNotNull( jwks );

				//jwksServer.AssertWasCalled( x => x.Get( GOOD_JWK_PATH ) );
				//jwksServer.AssertWasNotCalled( x => x.Get( GOOD_PATH + JWKS_PATH ) );

				Assert.IsTrue( jwks.TryGetKey( GOOD_JWK_ID, out JsonWebKey jwk ) );
				Assert.AreEqual( GOOD_JWK_ID, jwk.Id );
			}
		}

		[Test]
		public async Task RequestJwkAsync_StringKeyId_Success() {
			using( var handler = SetupJwkServer( out string host, hasJwk: true, jwkStatusCode: HttpStatusCode.OK ) )
			using( HttpClient httpClient = new HttpClient( handler ) ) {
				IJwksProvider jwksProvider = new JwksProvider(
					httpClient,
					jwksEndpoint: new Uri( host + GOOD_PATH + JWKS_PATH ),
					jwkEndpoint: new Uri( host + GOOD_PATH + JWK_PATH )
				);

				JsonWebKeySet jwks = await jwksProvider
					.RequestJwkAsync( GOOD_JWK_ID_STRING )
					.ConfigureAwait( false );
				Assert.IsNotNull( jwks );

				//jwksServer.AssertWasCalled( x => x.Get( GOOD_JWK_PATH ) );
				//jwksServer.AssertWasNotCalled( x => x.Get( GOOD_PATH + JWKS_PATH ) );

				Assert.IsTrue( jwks.TryGetKey( GOOD_JWK_ID_STRING, out JsonWebKey jwk ) );
				Assert.AreEqual( GOOD_JWK_ID_STRING, jwk.Id );
			}
		}

		[Test]
		public async Task RequestJwkAsync_StringKeyId_InvalidKeyId_Fallback_DoesNotReturnKey() {
			using( var handler = SetupJwkServer( out string host, hasJwk: true, jwkStatusCode: HttpStatusCode.OK ) )
			using( HttpClient httpClient = new HttpClient( handler ) ) {
				IJwksProvider jwksProvider = new JwksProvider(
					httpClient,
					jwksEndpoint: new Uri( host + GOOD_PATH + JWKS_PATH ),
					jwkEndpoint: new Uri( host + GOOD_PATH + JWK_PATH )
				);

				JsonWebKeySet jwks = await jwksProvider
					.RequestJwkAsync( "NJVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg" )
					.ConfigureAwait( false );
				Assert.IsNotNull( jwks );

				//jwksServer.AssertWasCalled( x => x.Get( GOOD_JWK_PATH ) );
				//jwksServer.AssertWasNotCalled( x => x.Get( GOOD_PATH + JWKS_PATH ) );

				Assert.IsFalse( jwks.TryGetKey( "NJVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg", out JsonWebKey jwk ) );
			}
		}

		[Test]
		public async Task RequestJwkAsync_404_Fallback_Success() {
			using( var handler = SetupJwkServer( out string host, hasJwk: false, jwkStatusCode: HttpStatusCode.NotFound ) )
			using( HttpClient httpClient = new HttpClient( handler ) ) {
				IJwksProvider jwksProvider = new JwksProvider(
					httpClient,
					jwksEndpoint: new Uri( host + GOOD_PATH + JWKS_PATH ),
					jwkEndpoint: new Uri( host + GOOD_PATH + JWK_PATH )
				);

				JsonWebKeySet jwks = await jwksProvider
					.RequestJwkAsync( GOOD_JWK_ID )
					.ConfigureAwait( false );
				Assert.IsNotNull( jwks );

				//jwksServer.AssertWasCalled( x => x.Get( GOOD_JWK_PATH ) );
				//jwksServer.AssertWasCalled( x => x.Get( GOOD_PATH + JWKS_PATH ) );

				Assert.IsTrue( jwks.TryGetKey( GOOD_JWK_ID, out JsonWebKey jwk ) );
				Assert.AreEqual( GOOD_JWK_ID, jwk.Id );
			}
		}

		[Test]
		public async Task RequestJwkAsync_StringKeyId_404_Fallback_Success() {
			using( var handler = SetupJwkServer( out string host, hasJwk: false, jwkStatusCode: HttpStatusCode.NotFound ) )
			using( HttpClient httpClient = new HttpClient( handler ) ) {
				IJwksProvider jwksProvider = new JwksProvider(
					httpClient,
					jwksEndpoint: new Uri( host + GOOD_PATH + JWKS_PATH ),
					jwkEndpoint: new Uri( host + GOOD_PATH + JWK_PATH )
				);

				JsonWebKeySet jwks = await jwksProvider
					.RequestJwkAsync( GOOD_JWK_ID_STRING )
					.ConfigureAwait( false );
				Assert.IsNotNull( jwks );

				//jwksServer.AssertWasCalled( x => x.Get( GOOD_JWK_PATH ) );
				//jwksServer.AssertWasCalled( x => x.Get( GOOD_PATH + JWKS_PATH ) );

				Assert.IsTrue( jwks.TryGetKey( GOOD_JWK_ID_STRING, out JsonWebKey jwk ) );
				Assert.AreEqual( GOOD_JWK_ID_STRING, jwk.Id );
			}
		}

		[Test]
		public async Task RequestJwkAsync_500_Fallback_Success() {
			using( var handler = SetupJwkServer( out string host, hasJwk: false, jwkStatusCode: HttpStatusCode.InternalServerError ) )
			using( HttpClient httpClient = new HttpClient( handler ) ) {
				IJwksProvider jwksProvider = new JwksProvider(
					httpClient,
					jwksEndpoint: new Uri( host + GOOD_PATH + JWKS_PATH ),
					jwkEndpoint: new Uri( host + GOOD_PATH + JWK_PATH )
				);

				JsonWebKeySet jwks = await jwksProvider
					.RequestJwkAsync( GOOD_JWK_ID )
					.ConfigureAwait( false );
				Assert.IsNotNull( jwks );

				//jwksServer.AssertWasCalled( x => x.Get( GOOD_JWK_PATH ) );
				//jwksServer.AssertWasCalled( x => x.Get( GOOD_PATH + JWKS_PATH ) );

				Assert.IsTrue( jwks.TryGetKey( GOOD_JWK_ID, out JsonWebKey jwk ) );
				Assert.AreEqual( GOOD_JWK_ID, jwk.Id );
			}
		}

		[Test]
		public async Task RequestJwkAsync_StringKeyId_500_Fallback_Success() {
			using( var handler = SetupJwkServer( out string host, hasJwk: false, jwkStatusCode: HttpStatusCode.InternalServerError ) )
			using( HttpClient httpClient = new HttpClient( handler ) ) {
				IJwksProvider jwksProvider = new JwksProvider(
					httpClient,
					jwksEndpoint: new Uri( host + GOOD_PATH + JWKS_PATH ),
					jwkEndpoint: new Uri( host + GOOD_PATH + JWK_PATH )
				);

				JsonWebKeySet jwks = await jwksProvider
					.RequestJwkAsync( GOOD_JWK_ID_STRING )
					.ConfigureAwait( false );
				Assert.IsNotNull( jwks );

				//jwksServer.AssertWasCalled( x => x.Get( GOOD_JWK_PATH ) );
				//jwksServer.AssertWasCalled( x => x.Get( GOOD_PATH + JWKS_PATH ) );

				Assert.IsTrue( jwks.TryGetKey( GOOD_JWK_ID_STRING, out JsonWebKey jwk ) );
				Assert.AreEqual( GOOD_JWK_ID_STRING, jwk.Id );
			}
		}

		[Test]
		public void Namespace_ReturnsJwksAbsoluteUri() {
			Uri jwksEndpoint = new Uri( "https://dev.auth.brightspace.com/core/.well-known/jwks" );
			IJwksProvider jwksProvider = new JwksProvider(
				httpClient: null,
				jwksEndpoint: jwksEndpoint,
				jwkEndpoint: null
			);

			Assert.AreEqual( jwksEndpoint.AbsoluteUri, jwksProvider.Namespace );
		}
	}
}
