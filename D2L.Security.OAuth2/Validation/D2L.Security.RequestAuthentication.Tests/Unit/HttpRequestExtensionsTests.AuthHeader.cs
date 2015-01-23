using System.Net.Http;
using NUnit.Framework;

namespace D2L.Security.RequestAuthentication.Tests.Unit {
	
	[TestFixture]
	internal partial class HttpRequestExtensionsTests {

		private const string BEARER_TOKEN_AUTHORIZATION_SCHEME = "Bearer";

		[Test]
		public void GetBearerTokenValue_Success() {
			Assert.Inconclusive();
		}

		[Test]
		public void GetBearerTokenValue_NullRequest_ExpectNull() {
			Assert.Inconclusive();
		}

		[Test]
		public void GetBearerTokenValue_NoAuthorizationHeader_ExpectNull() {
			Assert.Inconclusive();
		}

		[Test]
		public void GetBearerTokenValue_WrongScheme_ExpectNull() {
			Assert.Inconclusive();
		}
	}
}
