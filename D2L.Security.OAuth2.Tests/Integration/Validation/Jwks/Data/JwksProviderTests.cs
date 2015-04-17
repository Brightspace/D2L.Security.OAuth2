using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Runtime;
using System.Text;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Tests.Mocks;
using D2L.Security.OAuth2.Validation.Exceptions;
using D2L.Security.OAuth2.Validation.Jwks.Data;
using HttpMock;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Tests.Integration.Validation.Jwks.Data {
	
	[TestFixture]
	[Category("Integration")]
	public class JwksProviderTests {
		
		private const string GOOD_PATH = "/goodpath";
		private const string GOOD_JSON = "{\"keys\": []}";
		private const string BAD_PATH = "/badpath";

		private IHttpServer m_jwksServer;
		private string m_host;
		private IJwksProvider m_jwksProvider = new JwksProvider();
		
		[TestFixtureSetUp]
		public void TestFixtureSetUp() {

			m_jwksServer = HttpMockFactory.Create( out m_host );
			
			m_jwksServer.Stub(
				x => x.Get( GOOD_PATH )
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
		public async Task ErrorCase() {
			
			var badUri = new Uri( m_host + BAD_PATH );
			await m_jwksProvider.RequestJwksAsync( badUri );
			
		}
	}
}
