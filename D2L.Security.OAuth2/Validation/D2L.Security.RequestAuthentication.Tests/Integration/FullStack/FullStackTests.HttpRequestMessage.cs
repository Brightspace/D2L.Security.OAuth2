using System.Net.Http;
using D2L.Security.RequestAuthentication.Tests.Utilities;
using NUnit.Framework;

namespace D2L.Security.RequestAuthentication.Tests.Integration.FullStack {
	
	[TestFixture]
	internal sealed partial class FullStackTests {
		
		[Test]
		public void HttpRequestMessage_Cookie_WithXsrf_Success() {
			string cookieValue = TestTokens.ValidWithXsrfOneScope.Jwt;

			HttpRequestMessage httpRequestMessage = new HttpRequestMessage();
			RequestBuilder.AddCookie( httpRequestMessage, cookieValue );
			RequestBuilder.AddXsrfHeader( httpRequestMessage, TestTokens.ValidWithXsrfOneScope.Xt );
			
			ID2LPrincipal principal;
			AuthenticationResult result = m_authenticator.AuthenticateAndExtract( httpRequestMessage, out principal );
		}

		[Test]
		public void HttpRequestMessage_Cookie_NoXsrf_Success() {
			Assert.Inconclusive();
		}

		[Test]
		public void HttpRequestMessage_BearerToken_NoXsrf_Success() {
			Assert.Inconclusive();
		}

		[Test]
		public void HttpRequestMessage_BearerToken_WithXsrf_Success() {
			Assert.Inconclusive();
		}

		[Test]
		public void HttpRequestMessage_BearerToken_InvalidJwt_Failure() {
			Assert.Inconclusive();
		}

		[Test]
		public void HttpRequestMessage_Cookie_InvalidJwt_Failure() {
			Assert.Inconclusive();
		}

		[Test]
		public void HttpRequestMessage_Cookie_NonMatchingXsrf_Failure() {
			Assert.Inconclusive();
		}

		[Test]
		public void HttpRequestMessage_BearerToken_NonMatchingXsrf_Failure() {
			Assert.Inconclusive();
		}
	}
}
