using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

using D2L.Security.OAuth2.Provisioning;
using D2L.Security.OAuth2.Provisioning.Default;
using D2L.Security.OAuth2.Scopes;

using Moq;
using Moq.Protected;

using NUnit.Framework;

namespace D2L.Security.OAuth2.Tests.Unit.Provisioning.Default {

	[TestFixture]
	[Category( "Unit" )]
	internal sealed class AuthServiceClientTests {

		private class TestData {
			public const string ValidHttpResponseBody = "{\"access_token\":\"mrrrrrr\",\"expires_in\":3600,\"token_type\":\"Bearer\"}";
		}

		[Test]
		async public void CorrectlyEncodesBody_NoScope() {
			string requestBody = null;
			Action<string> requestBodyReceiver = x => requestBody = x;

			using( var client = CreateMockedClient( requestBodyReceiver ) ) {
				var assertion = "123";
				var result = await client.ProvisionAccessTokenAsync( assertion, Enumerable.Empty<Scope>() );

				var parameters = requestBody
					.Split( '&' )
					.Select( x => x.Split( '=' ) )
					.ToDictionary( x => x[0], x => x[1] );

				Assert.AreEqual( ProvisioningConstants.AssertionGrant.GRANT_TYPE, parameters["grant_type"] );
				Assert.AreEqual( assertion, parameters["assertion"] );
				Assert.AreEqual( string.Empty, parameters["scope"] );
			}
		}

		[Test]
		async public void CorrectlyEncodesBody_OneScope() {
			string requestBody = null;
			Action<string> requestBodyReceiver = x => requestBody = x;

			using( var client = CreateMockedClient( requestBodyReceiver ) ) {
				var assertion = "123";
				var result = await client.ProvisionAccessTokenAsync( assertion, new Scope[] {
					new Scope( "foo", "bar", "baz" )
				} );

				var parameters = requestBody
					.Split( '&' )
					.Select( x => x.Split( '=' ) )
					.ToDictionary( x => x[0], x => x[1] );

				Assert.AreEqual( ProvisioningConstants.AssertionGrant.GRANT_TYPE, parameters["grant_type"] );
				Assert.AreEqual( assertion, parameters["assertion"] );
				Assert.AreEqual( "foo%3Abar%3Abaz", parameters["scope"] );
			}
		}

		[Test]
		async public void CorrectlyEncodesBody_ManyScopes() {
			string requestBody = null;
			Action<string> requestBodyReceiver = x => requestBody = x;

			using( var client = CreateMockedClient( requestBodyReceiver ) ) {
				var assertion = "123";
				var result = await client.ProvisionAccessTokenAsync( assertion, new Scope[] {
					new Scope( "foo", "bar", "baz" ),
					new Scope( "quux", "mrr", "rawr" )
				} );

				var parameters = requestBody
					.Split( '&' )
					.Select( x => x.Split( '=' ) )
					.ToDictionary( x => x[0], x => x[1] );

				Assert.AreEqual( ProvisioningConstants.AssertionGrant.GRANT_TYPE, parameters["grant_type"] );
				Assert.AreEqual( assertion, parameters["assertion"] );
				Assert.AreEqual( "foo%3Abar%3Abaz+quux%3Amrr%3Arawr", parameters["scope"] );
			}
		}

		[Test]
		async public void CorrectlyReadsResponse() {
			using( var client = CreateMockedClient( x => { }, responseContent: TestData.ValidHttpResponseBody ) ) {
				var assertion = "123";
				var result = await client.ProvisionAccessTokenAsync( assertion, Enumerable.Empty<Scope>() );

				Assert.AreEqual( "mrrrrrr", result.Token );
				Assert.AreEqual( TimeSpan.FromHours( 1 ), result.ExpiresIn );
			}
		}

		private static IAuthServiceClient CreateMockedClient(
			Action<string> requestBodyReceiver,
			HttpStatusCode responseStatus = HttpStatusCode.OK,
			string responseContent = TestData.ValidHttpResponseBody
		) {
			var messageHandler = new Mock<HttpMessageHandler>();
			messageHandler
				.Protected()
				.Setup<Task<HttpResponseMessage>>(
					"SendAsync",
					ItExpr.IsAny<HttpRequestMessage>(),
					ItExpr.IsAny<CancellationToken>()
				)
				.Callback<HttpRequestMessage, CancellationToken>(
					// Use .Result because Callback doesn't await this function
					( req, _ ) => requestBodyReceiver( req.Content.ReadAsStringAsync().Result )
				)
				.ReturnsAsync( new HttpResponseMessage() {
					StatusCode = HttpStatusCode.OK,
					Content = new StringContent( TestData.ValidHttpResponseBody )
				} ); ;

			var httpClient = new HttpClient( messageHandler.Object, true );
			var client = new AuthServiceClient(
				httpClient: httpClient,
				disposeHttpClient: true,
				tokenProvisioningEndpoint: new Uri( "http://foo.d2l" )
			);

			return client;
		}

	}
}
