using System.Net.Http;
using NUnit.Framework;

namespace D2L.Security.RequestAuthentication.Tests.Unit {
	
	[TestFixture]
	internal partial class HttpRequestExtensionsTests {

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
			Assert.Inconclusive();
		}

		[Test]
		public void GetCookieValue_NullCookieName_ExpectNull() {
			Assert.Inconclusive();
		}

		[Test]
		public void GetCookieValue_EmptyCookieName_ExpectNull() {
			Assert.Inconclusive();
		}

		[Test]
		public void GetCookieValue_NoCookieHeader_ExpectNull() {
			Assert.Inconclusive();
		}

		[Test]
		public void GetCookieValue_NoCookies_ExpectNull() {
			Assert.Inconclusive();
		}
	}
}
