using System.Net.Http;
using System.Web;
using D2L.Security.RequestAuthentication.Tests.Utilities;
using NUnit.Framework;

namespace D2L.Security.RequestAuthentication.Tests.Unit {
	
	[TestFixture]
	internal partial class HttpRequestExtensionsTests {

		private readonly HttpRequest m_bareHttpRequest = new HttpRequest( null, "http://d2l.com", null );

		[Test]
		public void GetBearerTokenValue_Success() {
			string expected = "somevalue";
			HttpRequest httpRequest = new HttpRequest( null, "http://d2l.com", null )
				.WithAuthHeader( expected );
			Assert.AreEqual( expected, httpRequest.GetBearerTokenValue() );
		}

		[Test]
		public void GetBearerTokenValue_NullRequest_ExpectNull() {
			Assert.IsNull( HttpRequestExtensions.GetBearerTokenValue( null ) );
		}

		[Test]
		public void GetBearerTokenValue_NoAuthorizationHeader_ExpectNull() {
			Assert.IsNull( m_bareHttpRequest.GetBearerTokenValue() );
		}

		[Test]
		public void GetBearerTokenValue_WrongScheme_ExpectNull() {
			HttpRequest httpRequest = new HttpRequest( null, "http://d2l.com", null )
				.WithAuthHeader( "invalidscheme", "somevalue" );
			Assert.IsNull( httpRequest.GetBearerTokenValue() );
		}
	}
}
