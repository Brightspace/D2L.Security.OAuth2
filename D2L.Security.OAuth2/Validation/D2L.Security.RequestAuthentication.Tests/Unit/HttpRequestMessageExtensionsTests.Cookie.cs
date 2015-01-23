using System.Net.Http;
using NUnit.Framework;

namespace D2L.Security.RequestAuthentication.Tests.Unit {
	
	[TestFixture]
	internal partial class HttpRequestMessageExtensionsTests {

		private const string COOKIE_HEADER = "Cookie";

		[Test]
		public void GetCookieValue_SingleCookieValue_Success() {
			Assert.Inconclusive();
		}

		[Test]
		public void GetCookieValue_MultipleCookieValues_Success() {
			Assert.Inconclusive();
		}

		[Test]
		public void GetCookieValue_NullRequest_ExpectNull() {
			Assert.IsNull( HttpRequestMessageExtensions.GetCookieValue( null, "dummycookiename" ) );
		}

		[Test]
		public void GetCookieValue_NullCookieName_ExpectNull() {
			Assert.IsNull( new HttpRequestMessage().GetCookieValue( null ) );
		}

		[Test]
		public void GetCookieValue_EmptyCookieName_ExpectNull() {
			Assert.IsNull( new HttpRequestMessage().GetCookieValue( string.Empty ) );
		}

		[Test]
		public void GetCookieValue_NoCookieHeader_ExpectNull() {
			Assert.IsNull( new HttpRequestMessage().GetCookieValue( "dummycookiename" ) );
		}

		[Test]
		public void GetCookieValue_NoCookies_ExpectNull() {
			HttpRequestMessage request = new HttpRequestMessage();
			request.Headers.Add( COOKIE_HEADER, new string[] { } );
			Assert.IsNull( request.GetCookieValue( "dummycookiename" ) );
		}
	}
}
