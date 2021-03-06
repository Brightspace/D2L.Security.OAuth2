﻿using System;
using System.Net.Http;
using System.Net.Http.Headers;
using D2L.Security.OAuth2.TestUtilities;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Validation.Request {
	[TestFixture]
	internal partial class HttpRequestMessageExtensionsTests {
		private readonly HttpRequestMessage m_bareHttpRequestMessage = new HttpRequestMessage();

		[Test]
		public void GetBearerTokenValue_Success() {
			string expected = "somebearertokenvalue";
			HttpRequestMessage httpRequestMessage = new HttpRequestMessage();

			httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue(
				"Bearer",
				expected
			);
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
			HttpRequestMessage httpRequestMessage = new HttpRequestMessage();
			httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue(
				"invalidscheme",
				"somevalue"
			);
			Assert.IsNull( httpRequestMessage.GetBearerTokenValue() );
		}
	}
}
