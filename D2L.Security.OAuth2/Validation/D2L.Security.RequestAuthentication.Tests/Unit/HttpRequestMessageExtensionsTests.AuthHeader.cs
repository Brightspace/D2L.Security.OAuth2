using System.Net.Http;
using D2L.Security.RequestAuthentication.Tests.Utilities;
using NUnit.Framework;

namespace D2L.Security.RequestAuthentication.Tests.Unit {
	
	[TestFixture]
	internal partial class HttpRequestMessageExtensionsTests {

		private readonly HttpRequestMessage m_bareHttpRequestMessage = new HttpRequestMessage();

		[Test]
		public void GetBearerTokenValue_Success() {
			string expected = "somebearertokenvalue";
			HttpRequestMessage httpRequestMessage = new HttpRequestMessage();
			RequestBuilder.AddAuthHeader( httpRequestMessage, expected );
			Assert.AreEqual( expected, HttpRequestMessageExtensions.GetBearerTokenValue( httpRequestMessage ) );
		}
		
		[Test]
		public void GetBearerTokenValue_NullRequest_ExpectNull() {
			Assert.IsNull( HttpRequestMessageExtensions.GetBearerTokenValue( null ) );
		}

		[Test]
		public void GetBearerTokenValue_NoAuthorizationHeader_ExpectNull() {
			Assert.IsNull( HttpRequestMessageExtensions.GetBearerTokenValue( m_bareHttpRequestMessage ) );
		}

		[Test]
		public void GetBearerTokenValue_WrongScheme_ExpectNull() {
			HttpRequestMessage httpRequestMessage = new HttpRequestMessage();
			RequestBuilder.AddAuthHeader( httpRequestMessage, "invalidscheme", "somevalue" );
			Assert.IsNull( HttpRequestMessageExtensions.GetBearerTokenValue( httpRequestMessage) );
		}
	}
}
