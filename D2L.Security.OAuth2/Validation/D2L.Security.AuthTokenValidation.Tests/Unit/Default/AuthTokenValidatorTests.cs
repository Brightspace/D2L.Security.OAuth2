using System;
using System.Collections;
using System.Collections.Specialized;
using System.Reflection;
using System.Web;
using D2L.Security.AuthTokenValidation.Default;
using NUnit.Framework;

namespace D2L.Security.AuthTokenValidation.Tests.Unit.Default {

	[TestFixture]
	internal sealed class AuthTokenValidatorTests {

		private const string TOKEN_STUB = "abcde";

		private readonly IAuthTokenValidator m_authTokenValidator = new AuthTokenValidator( null );

		#region VerifyHeader Tests

		[Test]
		public void VerifyHeader_ValidHeader_Succeeds() {

			string jwtHeader = MakeJwtHeader( "RS256", "JWT" );

			AuthTokenValidator.VerifyHeader( jwtHeader );

			Assert.Pass();
		}

		[Test]
		public void VerifyHeader_WrongAlgorithm_Exception() {

			string jwtHeader = MakeJwtHeader( "ABCDE", "JWT" );
			Assert.Throws<AuthorizationException>( () => AuthTokenValidator.VerifyHeader( jwtHeader ) );
		}

		[Test]
		public void VerifyHeader_WrongType_Exception() {

			string jwtHeader = MakeJwtHeader( "RS256", "ABC" );
			Assert.Throws<AuthorizationException>( () => AuthTokenValidator.VerifyHeader( jwtHeader ) );
		}

		[Test]
		public void VerifyHeader_WrongTypeAndAlgorithm_Exception() {

			string jwtHeader = MakeJwtHeader( "ABCDE", "ABC" );
			Assert.Throws<AuthorizationException>( () => AuthTokenValidator.VerifyHeader( jwtHeader ) );
		}

		#endregion VerifyHeader Tests

		#region Token Fetching Tests

		[Test]
		public void GetTokenFromCookie_AuthCookiePresent_CookieMatchesExpected() {

			HttpRequest httpRequest = CreateHttpRequest();
			httpRequest.Cookies.Add( new HttpCookie( "d2lApi", TOKEN_STUB ) );

			string token = AuthTokenValidator.GetTokenFromCookie( httpRequest );
			Assert.AreEqual( TOKEN_STUB, token );
		}

		[Test]
		public void GetTokenFromCookie_AuthCookieNotPresent_NullReturned() {

			HttpRequest httpRequest = CreateHttpRequest();

			string token = AuthTokenValidator.GetTokenFromCookie( httpRequest );
			Assert.Null( token );
		}

		#endregion GetTokenFromCookie Tests

		#region GetTokenFromAuthHeader Tests

		[Test]
		public void GetTokenFromAuthHeader_AuthHeaderPresent_HeaderMatchesExpected() {

			HttpRequest httpRequest = CreateHttpRequest();
			AddAuthHeader( httpRequest, string.Format( "Bearer {0}", TOKEN_STUB ) );

			string token = AuthTokenValidator.GetTokenFromAuthHeader( httpRequest );
			Assert.AreEqual( TOKEN_STUB, token );
		}

		[Test]
		public void GetTokenFromAuthHeader_AuthHeaderNotPresent_NullReturned() {

			HttpRequest httpRequest = CreateHttpRequest();

			string token = AuthTokenValidator.GetTokenFromAuthHeader( httpRequest );
			Assert.Null( token );
		}

		[Test]
		public void GetTokenFromAuthHeader_InvalidTokenPrefix_NullReturned() {

			HttpRequest httpRequest = CreateHttpRequest();
			AddAuthHeader( httpRequest, string.Format( "NOT_BEARER {0}", TOKEN_STUB ) );

			string token = AuthTokenValidator.GetTokenFromAuthHeader( httpRequest );
			Assert.Null( token );
		}

		#endregion GetTokenFromAuthHeader Tests

		#region VerifyAndDecode Tests

		[Test]
		public void VerifyAndDecode_AuthTokenInBothHeaderAndCookie_ExpectException() {

			HttpRequest httpRequest = CreateHttpRequest();
			AddAuthHeader( httpRequest, string.Format( "Bearer {0}", TOKEN_STUB ) );
			httpRequest.Cookies.Add( new HttpCookie( "d2lApi", TOKEN_STUB ) );

			Assert.Throws<AuthorizationException>( () => m_authTokenValidator.VerifyAndDecode( httpRequest ) );
		}

		[Test]
		public void VerifyAndDecode_ExpectException() {
			Assert.Throws<AuthorizationException>( () => m_authTokenValidator.VerifyAndDecode( "AB.CD.EF.GH" ) );
		}

		[Test]
		public void VerifyAndDecode_JwtHasFewerThanThreeSegments_ExpectException() {
			Assert.Throws<AuthorizationException>( () => m_authTokenValidator.VerifyAndDecode( "AB.CD" ) );
		}

		[Test]
		public void VerifyAndDecode_JwtIsEmpty_ExpectException() {
			Assert.Throws<AuthorizationException>( () => m_authTokenValidator.VerifyAndDecode( string.Empty ) );
		}

		[Test]
		public void VerifyAndDecode_JwtHasEmptySegment_ExpectException() {
			Assert.Throws<AuthorizationException>( () => m_authTokenValidator.VerifyAndDecode( "AB..CD" ) );
		}

		#endregion VerifyAndDecode Tests

		private string MakeJwtHeader( string algorithm, string type ) {
			return string.Format( "{{ \"alg\": \"{0}\", \"typ\": \"{1}\"}}", algorithm, type );
		}

		private HttpRequest CreateHttpRequest() {
			return new HttpRequest( null, "http://www.google.ca", null );
		}

		private void AddAuthHeader( HttpRequest httpRequest, string authHeaderValue ) {

			// A hack for modifying http headers in an HttpRequest: http://stackoverflow.com/a/13307238
			NameValueCollection headers = httpRequest.Headers;
			Type headerCollectionType = headers.GetType();
			ArrayList item = new ArrayList();

			const BindingFlags flags = BindingFlags.InvokeMethod | BindingFlags.NonPublic | BindingFlags.Instance;

			headerCollectionType.InvokeMember( "MakeReadWrite", flags, null, headers, null );
			headerCollectionType.InvokeMember( "InvalidateCachedArrays", flags, null, headers, null );
			item.Add( authHeaderValue );
			headerCollectionType.InvokeMember( "BaseAdd", flags, null, headers, new object[] { "Authorization", item } );
			headerCollectionType.InvokeMember( "MakeReadOnly", flags, null, headers, null );
		}
	}
}
