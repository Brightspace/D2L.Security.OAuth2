using System;
using System.Web;
using D2L.Security.OAuth2.Validation.Request.Tests.Utilities;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Validation.Request.Tests.Unit {
	
	[TestFixture]
	internal partial class HttpRequestExtensionsTests {

		[Test]
		public void GetXsrfValue_Success() {
			string expected = "somecookievalue";
			HttpRequest httpRequest = RequestBuilder.Create()
				.WithXsrfHeader( expected );
			Assert.AreEqual( expected, httpRequest.GetXsrfValue() );
		}
		
		[Test]
		public void GetXsrfValue_NullRequest_ExpectNull() {
			Assert.Throws<NullReferenceException>(
				() => HttpRequestExtensions.GetXsrfValue( null )
				);
		}

		[Test]
		public void GetXsrfValue_NoXsrfHeader_ExpectNull() {
			Assert.IsNull( m_bareHttpRequest.GetXsrfValue() );
		}
	}
}
