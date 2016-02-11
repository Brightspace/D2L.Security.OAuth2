using System;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web;
using D2L.Security.OAuth2.Principal;
using D2L.Security.OAuth2.TestUtilities;
using D2L.Security.OAuth2.TestUtilities.Mocks;
using D2L.Security.OAuth2.Validation.AccessTokens;
using D2L.Security.OAuth2.Validation.Exceptions;
using Moq;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Validation.Request {
	[TestFixture]
	public class RequestAuthenticatorTests {
		private const string ACCESS_TOKEN = "some token";
		
		[Test]
		public async Task TokenInHeader_SuccessCase() {
			await RunTest(
				request_xsrfHeader: "xsrf",
				request_authorizationHeader: ACCESS_TOKEN,
				request_d2lApiCookie: null,
				accessToken_xsrfClaim: "xsrf",
				authMode: AuthenticationMode.Full
			).SafeAsync();
		}

		[Test]
		public async Task TokenInCookie_SuccessCase() {
			await RunTest(
				request_xsrfHeader: "xsrf",
				request_authorizationHeader: null,
				request_d2lApiCookie: ACCESS_TOKEN,
				accessToken_xsrfClaim: "xsrf",
				authMode: AuthenticationMode.Full
			).SafeAsync();
		}

		[Test]
		public async Task TokenInHeaderAndCookie_ThatsaNoNo() {
			await RunTest(
				request_xsrfHeader: "xsrf",
				request_authorizationHeader: ACCESS_TOKEN,
				request_d2lApiCookie: ACCESS_TOKEN,
				accessToken_xsrfClaim: "xsrf",
				authMode: AuthenticationMode.Full,
				expectedExceptionType: typeof( ValidationException )
			).SafeAsync();
		}

		[Test]
		public async Task NoToken() {
			await RunTest(
				request_xsrfHeader: "xsrf",
				request_authorizationHeader: string.Empty,
				request_d2lApiCookie: string.Empty,
				accessToken_xsrfClaim: "xsrf",
				authMode: AuthenticationMode.Full,
				expectedExceptionType: null,
				expected_principalType: PrincipalType.Anonymous
			).SafeAsync();
		}
		
		[Test]
		public async Task Xsrf_DoesNotMatch() {
			await RunTest(
				request_xsrfHeader: "xsrf",
				request_authorizationHeader: null,
				request_d2lApiCookie: ACCESS_TOKEN,
				accessToken_xsrfClaim: "XsRf",
				authMode: AuthenticationMode.Full,
				expectedExceptionType: typeof( XsrfException )
			).SafeAsync();
		}

		[Test]
		public async Task Xsrf_Mismatch_ButAuthModeIsSkipXsrf_SoItsAllGood() {
			await RunTest(
				request_xsrfHeader: "xsrf",
				request_authorizationHeader: null,
				request_d2lApiCookie: ACCESS_TOKEN,
				accessToken_xsrfClaim: "way different",
				authMode: AuthenticationMode.SkipXsrfValidation
			).SafeAsync();
		}

		[Test]
		public async Task TokenExpired() {
			await RunTest(
				request_xsrfHeader: "xsrf",
				request_authorizationHeader: null,
				request_d2lApiCookie: ACCESS_TOKEN,
				accessToken_xsrfClaim: "xsrf",
				authMode: AuthenticationMode.SkipXsrfValidation,
				expectedExceptionType: typeof( ExpiredTokenException )
			).SafeAsync();
		}

		[Test]
		public async Task WhenBothCookieAndHeaderSupplied_HeaderIsPreferred() {
			const string HEADER_TOKEN = "header";
			const string COOKIE_TOKEN = "cookie";

			var httpRequestMessage = new HttpRequestMessage()
				.WithAuthHeader( HEADER_TOKEN )
				.WithXsrfHeader( "xsrf" )
				.WithCookie( RequestValidationConstants.D2L_AUTH_COOKIE_NAME, COOKIE_TOKEN );

			IAccessToken token = AccessTokenMock.Create(
				xsrfClaim: "xsrf"
			).Object;

			Mock<IAccessTokenValidator> mock = new Mock<IAccessTokenValidator>();
			mock.Setup( v => v.ValidateAsync( HEADER_TOKEN ) ).ReturnsAsync( token );

			IRequestAuthenticator authenticator = new RequestAuthenticator( mock.Object );
			ID2LPrincipal result = await authenticator.AuthenticateAsync( httpRequestMessage ).SafeAsync();

			mock.Verify( v => v.ValidateAsync( HEADER_TOKEN ), Times.Exactly( 1 ) );
			Assert.NotNull( result );
		}

		private async Task RunTest(
			string request_xsrfHeader,
			string request_d2lApiCookie,
			string request_authorizationHeader,
			string accessToken_xsrfClaim,
			AuthenticationMode authMode,
			Type expectedExceptionType = null,
			PrincipalType? expected_principalType = null
		) {

			IAccessToken token = AccessTokenMock.Create(
				xsrfClaim: accessToken_xsrfClaim
			).Object;

			IAccessTokenValidator tokenValidator = AccessTokenValidatorMock.Create(
				accessToken: ACCESS_TOKEN,
				accessTokenAfterValidation: token,
				expectedExceptionType: expectedExceptionType
			).Object;

			IRequestAuthenticator authenticator = new RequestAuthenticator( tokenValidator );

			var httpRequestMessage = new HttpRequestMessage()
				.WithAuthHeader( request_authorizationHeader )
				.WithXsrfHeader( request_xsrfHeader )
				.WithCookie( RequestValidationConstants.D2L_AUTH_COOKIE_NAME, request_d2lApiCookie );

			ID2LPrincipal principal = null;
			Exception exception = null;
			try {
				principal = await authenticator.AuthenticateAsync(
					httpRequestMessage,
					authMode: authMode
					).SafeAsync();
			} catch( Exception e ) {
				exception = e;
			}
			
			CheckExpectations(
				principal,
				exception,
				expectedExceptionType,
				expected_principalType );

			exception = null;

			HttpRequest httpRequest = RequestBuilder.Create()
				.WithAuthHeader( request_authorizationHeader )
				.WithXsrfHeader( request_xsrfHeader )
				.WithCookie( RequestValidationConstants.D2L_AUTH_COOKIE_NAME, request_d2lApiCookie );

			try {
				principal = await authenticator.AuthenticateAsync(
					httpRequest,
					authMode: authMode
					).SafeAsync();
			} catch( Exception e ) {
				exception = e;
			}
			
			CheckExpectations(
				principal,
				exception,
				expectedExceptionType,
				expected_principalType );
		}

		private void CheckExpectations(
			ID2LPrincipal principal,
			Exception exception,
			Type expectedExceptionType,
			PrincipalType? expected_principalType
		) {
			if( expectedExceptionType != null ) {
				Assert.IsNull( principal );
				Assert.IsNotNull( exception );
				Assert.AreEqual( expectedExceptionType, exception.GetType() );
				return;
			}

			Assert.IsNotNull( principal );
			Assert.IsNull( exception );

			if( expected_principalType.HasValue ) {
				Assert.AreEqual( expected_principalType, principal.Type );
			}
		}
	}
}
