using System.Web;
using D2L.Security.RequestAuthentication.Tests.Utilities;
using NUnit.Framework;

namespace D2L.Security.RequestAuthentication.Tests.Unit {
	
	[TestFixture]
	internal partial class HttpRequestExtensionsTests {

		[Test]
		public void GetCookieValue_Single_Success() {
			string expected = "somecookievalue";
			HttpRequest httpRequest = RequestBuilder.Create()
				.WithCookie( expected );
			Assert.AreEqual( expected, httpRequest.GetCookieValue() );
		}

		[Test]
		public void GetCookieValue_Single_NotMatching_ExpectNull() {
			HttpRequest httpRequest = RequestBuilder.Create()
				.WithCookie( "invalidcookiename", "somecookievalue" );
			Assert.IsNull( httpRequest.GetCookieValue() );
		}

		[Test]
		public void GetCookieValue_Many_NoneMatching_ExpectNull() {
			HttpRequest httpRequest = RequestBuilder.Create()
				.WithCookie( "first", "somevalue" )
				.WithCookie( "second", "somevalue" );
			Assert.IsNull( httpRequest.GetCookieValue() );
		}

		[Test]
		public void GetCookieValue_Many_FirstMatches_Success() {
			string expected = "goodcookie";
			HttpRequest httpRequest = RequestBuilder.Create()
				.WithCookie( Constants.D2L_AUTH_COOKIE_NAME, expected )
				.WithCookie( "first", "somevalue" )
				.WithCookie( "second", "somevalue" );
			Assert.AreEqual( expected, httpRequest.GetCookieValue() );
		}

		[Test]
		public void GetCookieValue_Many_SecondMatches_Success() {
			string expected = "goodcookie";
			HttpRequest httpRequest = RequestBuilder.Create()
				.WithCookie( "first", "somevalue" )
				.WithCookie( Constants.D2L_AUTH_COOKIE_NAME, expected )
				.WithCookie( "second", "somevalue" );
			Assert.AreEqual( expected, httpRequest.GetCookieValue() );
		}

		[Test]
		public void GetCookieValue_Many_LastMatches_Success() {
			string expected = "goodcookie";
			HttpRequest httpRequest = RequestBuilder.Create()
				.WithCookie( "first", "somevalue" )
				.WithCookie( "second", "somevalue" )
				.WithCookie( Constants.D2L_AUTH_COOKIE_NAME, expected );
			Assert.AreEqual( expected, httpRequest.GetCookieValue() );
		}
		
		[Test]
		public void GetCookieValue_NullRequest_ExpectNull() {
			Assert.IsNull( HttpRequestExtensions.GetCookieValue( null ) );
		}
		
		[Test]
		public void GetCookieValue_NoCookies_ExpectNull() {
			Assert.IsNull( m_bareHttpRequest.GetCookieValue() );
		}
	}
}
