using System;
using System.Net.Http;
using D2L.Security.OAuth2.Validation.Request;
using D2L.Security.OAuth2.Validation.Request.Tests.Utilities;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Tests.Unit.Validation.Request {
	
	[TestFixture]
	[Category( "Unit" )]
	internal partial class HttpRequestMessageExtensionsTests {

		[Test]
		public void GetCookieValue_Single_Success() {
			string expected = "somecookievalue";
			HttpRequestMessage httpRequestMessage = new HttpRequestMessage()
				.WithCookie( expected );
			string cookieValue = httpRequestMessage.GetCookieValue();
			Assert.AreEqual( expected, cookieValue );
		}

		[Test]
		public void GetCookieValue_Single_NotMatching_ExpectNull() {
			HttpRequestMessage httpRequestMessage = new HttpRequestMessage()
				.WithCookie( "somecookiename", "somevalue" );
			Assert.IsNull( httpRequestMessage.GetCookieValue() );
		}

		[Test]
		public void GetCookieValue_Many_NoneMatching_ExpectNull() {
			string headerValue = CookieHeaderMaker.MakeCookieHeader(
				new Tuple<string, string>( "first", "value1" ),
				new Tuple<string, string>( "second", "value2" )
				);
			HttpRequestMessage httpRequestMessage = new HttpRequestMessage()
				.WithCookieHeader( headerValue );
			Assert.IsNull( httpRequestMessage.GetCookieValue() );
		}

		[Test]
		public void GetCookieValue_Many_FirstMatches_Success() {
			string expected = "goodcookievalue";
			string headerValue = CookieHeaderMaker.MakeCookieHeader(
				new Tuple<string, string>( RequestValidationConstants.D2L_AUTH_COOKIE_NAME, expected ),
				new Tuple<string, string>( "first", "value1" ),
				new Tuple<string, string>( "second", "value2" )
				);
			HttpRequestMessage httpRequestMessage = new HttpRequestMessage()
				.WithCookieHeader( headerValue );
			Assert.AreEqual( expected, httpRequestMessage.GetCookieValue() );
		}

		[Test]
		public void GetCookieValue_Many_MiddleMatches_Success() {
			string expected = "goodcookievalue";
			string headerValue = CookieHeaderMaker.MakeCookieHeader(
				new Tuple<string, string>( "first", "value1" ),
				new Tuple<string, string>( RequestValidationConstants.D2L_AUTH_COOKIE_NAME, expected ),
				new Tuple<string, string>( "second", "value2" )
				);
			HttpRequestMessage httpRequestMessage = new HttpRequestMessage()
				.WithCookieHeader( headerValue );
			Assert.AreEqual( expected, httpRequestMessage.GetCookieValue() );
		}

		[Test]
		public void GetCookieValue_Many_LastMatches_Success() {
			string expected = "goodcookievalue";
			string headerValue = CookieHeaderMaker.MakeCookieHeader(
				new Tuple<string, string>( "first", "value1" ),
				new Tuple<string, string>( "second", "value2" ),
				new Tuple<string, string>( RequestValidationConstants.D2L_AUTH_COOKIE_NAME, expected )
				);
			HttpRequestMessage httpRequestMessage = new HttpRequestMessage()
				.WithCookieHeader( headerValue );
			Assert.AreEqual( expected, httpRequestMessage.GetCookieValue() );
		}

		[Test]
		public void GetCookieValue_Many_EmptyCookie_BeforeMatchingCookie_Success() {
			string expected = "goodcookievalue";
			string headerValue = CookieHeaderMaker.MakeCookieHeader(
				new Tuple<string, string>( "first", string.Empty ),
				new Tuple<string, string>( RequestValidationConstants.D2L_AUTH_COOKIE_NAME, expected )
				);
			HttpRequestMessage httpRequestMessage = new HttpRequestMessage()
				.WithCookieHeader( headerValue );
			Assert.AreEqual( expected, httpRequestMessage.GetCookieValue() );
		}

		[Test]
		public void GetCookieValue_EmptyHeader_ExpectNull() {
			HttpRequestMessage httpRequestMessage = new HttpRequestMessage()
				.WithCookieHeader( string.Empty );
			Assert.IsNull( httpRequestMessage.GetCookieValue() );
		}

		[Test]
		public void GetCookieValue_NullHeader_ExpectNull() {
			HttpRequestMessage httpRequestMessage = new HttpRequestMessage()
				.WithCookieHeader( null );
			Assert.IsNull( httpRequestMessage.GetCookieValue() );
		}

		[Test]
		public void GetCookieValue_NullRequest_Throws() {
			Assert.Throws<NullReferenceException>( 
				() => HttpRequestMessageExtensions.GetCookieValue( null ) 
				);
		}
		
		[Test]
		public void GetCookieValue_NoCookieHeader_ExpectNull() {
			Assert.IsNull( m_bareHttpRequestMessage.GetCookieValue() );
		}

		[Test]
		public void GetCookieValue_NoCookies_ExpectNull() {
			HttpRequestMessage request = new HttpRequestMessage();
			request.Headers.Add( RequestValidationConstants.Headers.COOKIE, new string[] { } );
			Assert.IsNull( request.GetCookieValue() );
		}
	}
}
