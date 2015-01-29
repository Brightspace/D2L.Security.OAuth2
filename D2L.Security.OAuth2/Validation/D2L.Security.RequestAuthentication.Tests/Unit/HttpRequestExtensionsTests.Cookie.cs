using System.Web;
using D2L.Security.RequestAuthentication.Tests.Utilities;
using NUnit.Framework;

namespace D2L.Security.RequestAuthentication.Tests.Unit {
	
	[TestFixture]
	internal partial class HttpRequestExtensionsTests {

		[Test]
		public void GetCookieValue_Single_Success() {
			string expected = "somecookievalue";
			HttpRequest httpRequest = new HttpRequest( null, "http://d2l.com", null )
				.WithCookie( expected );
			Assert.AreEqual( expected, HttpRequestExtensions.GetCookieValue( httpRequest, Constants.D2L_AUTH_COOKIE_NAME ) );
		}

		[Test]
		public void GetCookieValue_Single_Mismatch_ExpectNull() {
			Assert.Inconclusive();
		}

		[Test]
		public void GetCookieValue_Many_First_Success() {
			Assert.Inconclusive();
		}

		[Test]
		public void GetCookieValue_Many_Middle_Success() {
			Assert.Inconclusive();
		}

		[Test]
		public void GetCookieValue_Many_Last_Success() {
			Assert.Inconclusive();
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
