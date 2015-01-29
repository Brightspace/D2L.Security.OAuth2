using System.Web;
using D2L.Security.RequestAuthentication.Tests.Utilities;
using NUnit.Framework;

namespace D2L.Security.RequestAuthentication.Tests.Unit {
	
	[TestFixture]
	internal partial class HttpRequestExtensionsTests {

		[Test]
		public void GetXsrfValue_Success() {
			string expected = "somecookievalue";
			HttpRequest httpRequest = new HttpRequest( null, "http://d2l.com", null )
				.WithXsrfHeader( expected );
			Assert.AreEqual( expected, httpRequest.GetXsrfValue() );
		}
		
		[Test]
		public void GetXsrfValue_NullRequest_ExpectNull() {
			Assert.IsNull( HttpRequestExtensions.GetXsrfValue( null ) );
		}

		[Test]
		public void GetXsrfValue_NoXsrfHeader_ExpectNull() {
			Assert.IsNull( m_bareHttpRequest.GetXsrfValue() );
		}
	}
}
