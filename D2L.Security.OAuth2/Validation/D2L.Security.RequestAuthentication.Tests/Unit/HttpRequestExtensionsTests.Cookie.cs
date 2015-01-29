using System.Web;
using D2L.Security.RequestAuthentication.Tests.Utilities;
using NUnit.Framework;

namespace D2L.Security.RequestAuthentication.Tests.Unit {
	
	[TestFixture]
	internal partial class HttpRequestExtensionsTests {

		[Test]
		public void GetCookieValue_Success() {
			string expected = "somecookievalue";
			HttpRequest httpRequest = new HttpRequest( null, "http://d2l.com", null );
			RequestBuilder.AddCookie( httpRequest, expected );
			Assert.AreEqual( expected, HttpRequestExtensions.GetCookieValue( httpRequest, Constants.D2L_AUTH_COOKIE_NAME ) );
		}
		
		[Test]
		public void GetCookieValue_NullRequest_ExpectNull() {
			Assert.IsNull( HttpRequestExtensions.GetCookieValue( null, "somecookiename" ) );
		}

		[Test]
		public void GetCookieValue_NullCookieName_ExpectNull() {
			Assert.IsNull( HttpRequestExtensions.GetCookieValue( m_bareHttpRequest, null ) );
		}

		[Test]
		public void GetCookieValue_EmptyCookieName_ExpectNull() {
			Assert.IsNull( HttpRequestExtensions.GetCookieValue( m_bareHttpRequest, string.Empty ) );
		}

		[Test]
		public void GetCookieValue_NoCookies_ExpectNull() {
			Assert.IsNull( HttpRequestExtensions.GetCookieValue( m_bareHttpRequest, "somecookiename" ) );
		}
	}
}
