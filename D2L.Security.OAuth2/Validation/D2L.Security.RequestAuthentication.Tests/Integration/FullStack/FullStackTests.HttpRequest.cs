using System.Net.Http;
using D2L.Security.RequestAuthentication.Tests.Utilities;
using NUnit.Framework;

namespace D2L.Security.RequestAuthentication.Tests.Integration.FullStack {
	
	[TestFixture]
	internal sealed partial class FullStackTests {

		[Test]
		public void HttpRequest_Cookie_NoXsrf_Success() {
			Assert.Inconclusive();
		}

		[Test]
		public void HttpRequest_Cookie_WithXsrf_Success() {
			Assert.Inconclusive();
		}

		[Test]
		public void HttpRequest_BearerToken_NoXsrf_Success() {
			Assert.Inconclusive();
		}

		[Test]
		public void HttpRequest_BearerToken_WithXsrf_Success() {
			Assert.Inconclusive();
		}

		[Test]
		public void HttpRequest_BearerToken_InvalidJwt_Failure() {
			Assert.Inconclusive();
		}

		[Test]
		public void HttpRequest_Cookie_InvalidJwt_Failure() {
			Assert.Inconclusive();
		}

		[Test]
		public void HttpRequest_Cookie_NonMatchingXsrf_Failure() {
			Assert.Inconclusive();
		}

		[Test]
		public void HttpRequest_BearerToken_NonMatchingXsrf_Failure() {
			Assert.Inconclusive();
		}
	}
}
