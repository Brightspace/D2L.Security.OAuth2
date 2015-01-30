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
			Assert.AreEqual( expected, httpRequest.GetCookieValue( Constants.D2L_AUTH_COOKIE_NAME ) );
		}

		[Test]
		public void GetCookieValue_Single_NotMatching_ExpectNull() {
			HttpRequest httpRequest = new HttpRequest( null, "http://d2l.com", null )
				.WithCookie( "invalidcookiename", "somecookievalue" );
			Assert.IsNull( httpRequest.GetCookieValue( Constants.D2L_AUTH_COOKIE_NAME ) );
		}

		[Test]
		public void GetCookieValue_Many_NoneMatching_ExpectNull() {
			HttpRequest httpRequest = new HttpRequest( null, "http://d2l.com", null )
				.WithCookie( "first", "somevalue" )
				.WithCookie( "second", "somevalue" );
			Assert.IsNull( httpRequest.GetCookieValue( Constants.D2L_AUTH_COOKIE_NAME ) );
		}

		[Test]
		public void GetCookieValue_Many_First_Success() {
			string expected = "goodcookie";
			HttpRequest httpRequest = new HttpRequest( null, "http://d2l.com", null )
				.WithCookie( "first", "somevalue" )
				.WithCookie( Constants.D2L_AUTH_COOKIE_NAME, expected )
				.WithCookie( "second", "somevalue" );
			Assert.AreEqual( expected, httpRequest.GetCookieValue( Constants.D2L_AUTH_COOKIE_NAME ) );
		}
		
		[Test]
		public void GetCookieValue_NullRequest_ExpectNull() {
			Assert.IsNull( HttpRequestExtensions.GetCookieValue( null, "somecookiename" ) );
		}

		[Test]
		public void GetCookieValue_NullCookieName_ExpectNull() {
			Assert.IsNull( m_bareHttpRequest.GetCookieValue( null ) );
		}

		[Test]
		public void GetCookieValue_EmptyCookieName_ExpectNull() {
			Assert.IsNull( m_bareHttpRequest.GetCookieValue( string.Empty ) );
		}

		[Test]
		public void GetCookieValue_NoCookies_ExpectNull() {
			Assert.IsNull( m_bareHttpRequest.GetCookieValue( "somecookiename" ) );
		}
	}
}
