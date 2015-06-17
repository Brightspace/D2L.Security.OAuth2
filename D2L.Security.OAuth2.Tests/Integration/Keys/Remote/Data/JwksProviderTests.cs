using System;
using System.Net;
using System.Threading.Tasks;

using D2L.Security.OAuth2.Keys.Remote.Data;
using D2L.Security.OAuth2.Tests.Utilities.Mocks;
using D2L.Security.OAuth2.Validation.Exceptions;
using HttpMock;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Tests.Integration.Keys.Remote.Data {
	
	[TestFixture]
	[Category("Integration")]
	public class JwksProviderTests {
		
		private const string GOOD_PATH = "/goodpath";
		private const string GOOD_PATH_WITH_JWKS = GOOD_PATH + "/.well-known/jwks";
		private const string GOOD_JSON = "{\"keys\": []}";
		private const string BAD_PATH = "/badpath";

		private IHttpServer m_jwksServer;
		private string m_host;
		private IJwksProvider m_jwksProvider = new JwksProvider();
		
		[TestFixtureSetUp]
		public void TestFixtureSetUp() {

			m_jwksServer = HttpMockFactory.Create( out m_host );
			
			m_jwksServer.Stub(
				x => x.Get( GOOD_PATH_WITH_JWKS )
			).Return( GOOD_JSON ).OK();
			
			m_jwksServer.Stub(
				x => x.Get( BAD_PATH )
			).Return( GOOD_JSON ).WithStatus( HttpStatusCode.InternalServerError );
			
		}

		[TestFixtureTearDown]
		public void TestFixtureTearDown() {
			if( m_jwksServer != null ) {
				m_jwksServer.Dispose();
			}
		}

		[Test]
		public async Task SuccessCase() {
			var goodUri = new Uri( m_host + GOOD_PATH );
			JwksResponse jwksResponse = await m_jwksProvider.RequestJwksAsync( goodUri );
			Assert.AreEqual( GOOD_JSON, jwksResponse.JwksJson );
		}

		[Test]
		[ExpectedException( typeof( PublicKeyLookupFailureException ) )]
		public async Task RequestJwksAsync_404_Throws() {
			var badUri = new Uri( m_host + BAD_PATH );
			await m_jwksProvider.RequestJwksAsync( badUri );
		}

		[Test]
		[ExpectedException( typeof( PublicKeyLookupFailureException ) )]
		public async Task RequestJwksAsync_CantReachServer_Throws() {
			var badUri = new Uri( "http://foo.bar.fakesite.isurehopethisisneveravalidTLD" );
			await m_jwksProvider.RequestJwksAsync( badUri );
		}
	}
}
