using NUnit.Framework;

namespace D2L.Security.RequestAuthentication.Tests.Unit {
	
	[TestFixture]
	internal partial class HttpRequestExtensionsTests {

		private const string XSRF_HEADER = "X-Csrf-Token";

		[Test]
		public void GetXsrfValue_Success() {
			Assert.Inconclusive();
		}
		
		[Test]
		public void GetXsrfValue_NullRequest_ExpectNull() {
			Assert.Inconclusive();
		}

		[Test]
		public void GetXsrfValue_NoXsrfHeader_ExpectNull() {
			Assert.Inconclusive();
		}
	}
}
