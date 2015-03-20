using System;
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
			HttpRequestMessage httpRequestMessage = new HttpRequestMessage()
				.WithAuthHeader( expected );
			Assert.AreEqual( expected, httpRequestMessage.GetBearerTokenValue() );
		}
		
		[Test]
		public void GetBearerTokenValue_NullRequest_ExpectNull() {
			Assert.Throws<NullReferenceException>(
				() => HttpRequestMessageExtensions.GetBearerTokenValue( null )
				);
		}

		[Test]
		public void GetBearerTokenValue_NoAuthorizationHeader_ExpectNull() {
			Assert.IsNull( m_bareHttpRequestMessage.GetBearerTokenValue() );
		}

		[Test]
		public void GetBearerTokenValue_WrongScheme_ExpectNull() {
			HttpRequestMessage httpRequestMessage = new HttpRequestMessage()
				.WithAuthHeader( "invalidscheme", "somevalue" );
			Assert.IsNull( httpRequestMessage.GetBearerTokenValue() );
		}
	}
}
