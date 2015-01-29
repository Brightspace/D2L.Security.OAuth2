using System.Net.Http;
using D2L.Security.RequestAuthentication.Tests.Utilities;
using NUnit.Framework;

namespace D2L.Security.RequestAuthentication.Tests.Unit {
	
	[TestFixture]
	internal partial class HttpRequestMessageExtensionsTests {

		[Test]
		public void GetCookieValue_Single_Success() {
			string expected = "somecookievalue";
			HttpRequestMessage httpRequestMessage = new HttpRequestMessage()
				.WithCookie( expected );
			string cookieValue = httpRequestMessage.GetCookieValue( Constants.D2L_AUTH_COOKIE_NAME );
			Assert.AreEqual( expected, cookieValue );
		}

		[Test]
		public void GetCookieValue_Single_NotMatching_ExpectNull() {
			Assert.Inconclusive();
		}

		[Test]
		public void GetCookieValue_Many_NoneMatching_ExpectNull() {
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
			Assert.IsNull( HttpRequestMessageExtensions.GetCookieValue( null, "dummycookiename" ) );
		}

		[Test]
		public void GetCookieValue_NullCookieName_ExpectNull() {
			Assert.IsNull( m_bareHttpRequestMessage.GetCookieValue( null ) );
		}

		[Test]
		public void GetCookieValue_EmptyCookieName_ExpectNull() {
			Assert.IsNull( m_bareHttpRequestMessage.GetCookieValue( string.Empty ) );
		}

		[Test]
		public void GetCookieValue_NoCookieHeader_ExpectNull() {
			Assert.IsNull( m_bareHttpRequestMessage.GetCookieValue( "dummycookiename" ) );
		}

		[Test]
		public void GetCookieValue_NoCookies_ExpectNull() {
			HttpRequestMessage request = new HttpRequestMessage();
			request.Headers.Add( Constants.Headers.COOKIE, new string[] { } );
			Assert.IsNull( request.GetCookieValue( "dummycookiename" ) );
		}
	}
}
