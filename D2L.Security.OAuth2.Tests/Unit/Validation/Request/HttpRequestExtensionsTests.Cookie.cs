using System;
using System.Web;
using D2L.Security.OAuth2.Validation.Request;
using D2L.Security.OAuth2.Validation.Request.Tests.Utilities;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Tests.Unit.Validation.Request {
	
	[TestFixture]
	[Category( "Unit" )]
	internal partial class HttpRequestExtensionsTests {

		[Test]
		public void GetCookieValue_Single_Success() {
			string expected = "somecookievalue";
			HttpRequest httpRequest = RequestBuilder.Create()
				.WithCookie( expected );
			Assert.AreEqual( expected, httpRequest.GetCookieValue() );
		}

		[Test]
		public void GetCookieValue_Single_NotMatching_ExpectNull() {
			HttpRequest httpRequest = RequestBuilder.Create()
				.WithCookie( "invalidcookiename", "somecookievalue" );
			Assert.IsNull( httpRequest.GetCookieValue() );
		}

		[Test]
		public void GetCookieValue_Many_NoneMatching_ExpectNull() {
			HttpRequest httpRequest = RequestBuilder.Create()
				.WithCookie( "first", "somevalue" )
				.WithCookie( "second", "somevalue" );
			Assert.IsNull( httpRequest.GetCookieValue() );
		}

		[Test]
		public void GetCookieValue_Many_FirstMatches_Success() {
			string expected = "goodcookie";
			HttpRequest httpRequest = RequestBuilder.Create()
				.WithCookie( RequestValidationConstants.D2L_AUTH_COOKIE_NAME, expected )
				.WithCookie( "first", "somevalue" )
				.WithCookie( "second", "somevalue" );
			Assert.AreEqual( expected, httpRequest.GetCookieValue() );
		}

		[Test]
		public void GetCookieValue_Many_SecondMatches_Success() {
			string expected = "goodcookie";
			HttpRequest httpRequest = RequestBuilder.Create()
				.WithCookie( "first", "somevalue" )
				.WithCookie( RequestValidationConstants.D2L_AUTH_COOKIE_NAME, expected )
				.WithCookie( "second", "somevalue" );
			Assert.AreEqual( expected, httpRequest.GetCookieValue() );
		}

		[Test]
		public void GetCookieValue_Many_LastMatches_Success() {
			string expected = "goodcookie";
			HttpRequest httpRequest = RequestBuilder.Create()
				.WithCookie( "first", "somevalue" )
				.WithCookie( "second", "somevalue" )
				.WithCookie( RequestValidationConstants.D2L_AUTH_COOKIE_NAME, expected );
			Assert.AreEqual( expected, httpRequest.GetCookieValue() );
		}
		
		[Test]
		public void GetCookieValue_NullRequest_ExpectNull() {
			Assert.Throws<NullReferenceException>(
				() => HttpRequestExtensions.GetCookieValue( null )
				);
		}
		
		[Test]
		public void GetCookieValue_NoCookies_ExpectNull() {
			Assert.IsNull( m_bareHttpRequest.GetCookieValue() );
		}
	}
}
