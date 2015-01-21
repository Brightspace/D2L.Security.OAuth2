using System;
using System.Collections;
using System.Collections.Specialized;
using System.IdentityModel.Tokens;
using System.Reflection;
using System.Web;
using D2L.Security.AuthTokenValidation.Default;
using D2L.Security.AuthTokenValidation.Tests.Utilities;
using D2L.Security.AuthTokenValidation.TokenValidation;
using Moq;
using NUnit.Framework;

namespace D2L.Security.AuthTokenValidation.Tests.Unit.Default {

	[TestFixture]
	internal sealed class AuthTokenValidatorTests {

		private const string TOKEN_STUB = "abcde";

		private readonly IAuthTokenValidator m_authTokenValidator = new AuthTokenValidator( null );

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
			HttpRequestBuilder.AddAuthHeader( httpRequest, string.Format( "Bearer {0}", TOKEN_STUB ) );

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
			HttpRequestBuilder.AddAuthHeader( httpRequest, string.Format( "NOT_BEARER {0}", TOKEN_STUB ) );

			string token = AuthTokenValidator.GetTokenFromAuthHeader( httpRequest );
			Assert.Null( token );
		}

		#endregion GetTokenFromAuthHeader Tests

		#region VerifyAndDecode Tests

		[Test]
		public void VerifyAndDecode_AuthTokenInBothHeaderAndCookie_ExpectException() {

			HttpRequest httpRequest = CreateHttpRequest();
			HttpRequestBuilder.AddAuthHeader( httpRequest, string.Format( "Bearer {0}", TOKEN_STUB ) );
			httpRequest.Cookies.Add( new HttpCookie( "d2lApi", TOKEN_STUB ) );

			Assert.Throws<AuthorizationException>( () => m_authTokenValidator.VerifyAndDecode( httpRequest ) );
		}

		[Test]
		public void VerifyAndDecode_String_Expired_ExpectAuthorizationException() {
			ArgumentException innerException = new ArgumentException();
			IAuthTokenValidator validator = MakeValidatorWhichThrows( innerException );

			Assertions.ThrowsWithInner<AuthorizationException>(
				() => validator.VerifyAndDecode( string.Empty ),
				innerException
				);
		}

		[Test]
		public void VerifyAndDecode_String_Expired_ExpectTokenExpiredException() {
			SecurityTokenExpiredException innerException = new SecurityTokenExpiredException();
			IAuthTokenValidator validator = MakeValidatorWhichThrows( innerException );

			Assertions.ThrowsWithInner<TokenExpiredException>(
				() => validator.VerifyAndDecode( string.Empty ),
				innerException
				);
		}

		[Test]
		public void VerifyAndDecode_HttpRequest_Expired_ExpectAuthorizationException() {
			HttpRequest httpRequest = CreateHttpRequest();
			httpRequest.Cookies.Add( new HttpCookie( "d2lApi", TOKEN_STUB ) );

			ArgumentException innerException = new ArgumentException();
			IAuthTokenValidator validator = MakeValidatorWhichThrows( innerException );

			Assertions.ThrowsWithInner<AuthorizationException>(
				() => validator.VerifyAndDecode( httpRequest ),
				innerException
				);
		}

		[Test]
		public void VerifyAndDecode_HttpRequest_Expired_ExpectTokenExpiredException() {
			HttpRequest httpRequest = CreateHttpRequest();
			httpRequest.Cookies.Add( new HttpCookie( "d2lApi", TOKEN_STUB ) );

			SecurityTokenExpiredException innerException = new SecurityTokenExpiredException();
			IAuthTokenValidator validator = MakeValidatorWhichThrows( innerException );

			Assertions.ThrowsWithInner<TokenExpiredException>(
				() => validator.VerifyAndDecode( string.Empty ),
				innerException
				);
		}

		private IAuthTokenValidator MakeValidatorWhichThrows( Exception innerException ) {
			Mock<IJWTValidator> jwtValidator = new Mock<IJWTValidator>();
			jwtValidator.Setup( x => x.Validate( It.IsAny<string>() ) ).Throws( innerException );
			IAuthTokenValidator validator = new AuthTokenValidator( jwtValidator.Object );
			return validator;
		}

		#endregion VerifyAndDecode Tests

		private HttpRequest CreateHttpRequest() {
			return new HttpRequest( null, "http://www.google.ca", null );
		}
	}
}
