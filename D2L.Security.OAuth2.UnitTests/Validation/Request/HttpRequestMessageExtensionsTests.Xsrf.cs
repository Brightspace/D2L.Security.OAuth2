using System;
using System.Net.Http;
using D2L.Security.OAuth2.TestUtilities;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Validation.Request {
	[TestFixture]
	internal partial class HttpRequestMessageExtensionsTests {

		[Test]
		public void GetXsrfValue_Success() {
			string expected = "somexsrfvalue";
			HttpRequestMessage httpRequestMessage = new HttpRequestMessage()
				.WithXsrfHeader( expected );
			Assert.AreEqual( expected, httpRequestMessage.GetXsrfValue() );
		}
		
		[Test]
		public void GetXsrfValue_NullRequest_ExpectNull() {
			Assert.Throws<NullReferenceException>(
				() => HttpRequestMessageExtensions.GetXsrfValue( null )
				);
		}

		[Test]
		public void GetXsrfValue_NoXsrfHeader_ExpectNull() {
			Assert.IsNull( m_bareHttpRequestMessage.GetXsrfValue() );
		}
	}
}
