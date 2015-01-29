using System.Net.Http;
using D2L.Security.RequestAuthentication.Tests.Utilities;
using NUnit.Framework;

namespace D2L.Security.RequestAuthentication.Tests.Unit {
	
	[TestFixture]
	internal partial class HttpRequestMessageExtensionsTests {

		[Test]
		public void GetXsrfValue_Success() {
			string expected = "somebearertokenvalue";
			HttpRequestMessage httpRequestMessage = new HttpRequestMessage()
				.WithXsrfHeader( expected );
			Assert.AreEqual( expected, HttpRequestMessageExtensions.GetXsrfValue( httpRequestMessage ) );
		}
		
		[Test]
		public void GetXsrfValue_NullRequest_ExpectNull() {
			Assert.IsNull( HttpRequestMessageExtensions.GetXsrfValue( null ) );
		}

		[Test]
		public void GetXsrfValue_NoXsrfHeader_ExpectNull() {
			Assert.IsNull( HttpRequestMessageExtensions.GetXsrfValue( m_bareHttpRequestMessage ) );
		}
	}
}
