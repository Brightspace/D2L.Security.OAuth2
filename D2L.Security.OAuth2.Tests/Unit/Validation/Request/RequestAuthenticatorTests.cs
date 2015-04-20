using System;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web;
using D2L.Security.OAuth2.Tests.Mocks;
using D2L.Security.OAuth2.Validation.AccessTokens;
using D2L.Security.OAuth2.Validation.Request;
using D2L.Security.OAuth2.Validation.Request.Tests.Utilities;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Tests.Unit.Validation.Request {
	
	[TestFixture]
	[Category( "Unit" )]
	public class RequestAuthenticatorTests {

		private const string ACCESS_TOKEN = "some token";
		private const string BEARER_TOKEN = RequestValidationConstants.BearerTokens.SCHEME_PREFIX + ACCESS_TOKEN;

		[Test]
		public void TokenInHeader_SuccessCase() {
			RunTest(
				request_xsrfHeader: "xsrf",
				request_authorizationHeader: BEARER_TOKEN,
				request_d2lApiCookie: null,
				accessToken_xsrfClaim: "xsrf",
				accessToken_validationStatus: ValidationStatus.Success,
				authMode: AuthenticationMode.Full,
 				expected_authenticationStatus: AuthenticationStatus.Success,
				expected_nullPrincipal: false
			);
		}

		[Test]
		public void TokenInCookie_SuccessCase() {
			RunTest(
				request_xsrfHeader: "xsrf",
				request_authorizationHeader: null,
				request_d2lApiCookie: ACCESS_TOKEN,
				accessToken_xsrfClaim: "xsrf",
				accessToken_validationStatus: ValidationStatus.Success,
				authMode: AuthenticationMode.Full,
 				expected_authenticationStatus: AuthenticationStatus.Success,
				expected_nullPrincipal: false
			);
		}

		[Test]
		public void TokenInHeaderAndCookie_ThatsaNoNo() {
			RunTest(
				request_xsrfHeader: "xsrf",
				request_authorizationHeader: BEARER_TOKEN,
				request_d2lApiCookie: ACCESS_TOKEN,
				accessToken_xsrfClaim: "xsrf",
				accessToken_validationStatus: ValidationStatus.Success,
				authMode: AuthenticationMode.Full,
 				expected_authenticationStatus: AuthenticationStatus.LocationConflict,
				expected_nullPrincipal: false
			);
		}

		[Test]
		public void NoToken() {
			RunTest(
				request_xsrfHeader: "xsrf",
				request_authorizationHeader: BEARER_TOKEN,
				request_d2lApiCookie: ACCESS_TOKEN,
				accessToken_xsrfClaim: "xsrf",
				accessToken_validationStatus: ValidationStatus.Success,
				authMode: AuthenticationMode.Full,
 				expected_authenticationStatus: AuthenticationStatus.Anonymous,
				expected_nullPrincipal: false
			);
		}


		[Test]
		public void Xsrf_DoesNotMatch() {
			RunTest(
				request_xsrfHeader: "xsrf",
				request_authorizationHeader: null,
				request_d2lApiCookie: ACCESS_TOKEN,
				accessToken_xsrfClaim: "XsRf",
				accessToken_validationStatus: ValidationStatus.Success,
				authMode: AuthenticationMode.Full,
 				expected_authenticationStatus: AuthenticationStatus.XsrfMismatch,
				expected_nullPrincipal: true
			);
		}

		[Test]
		public void Xsrf_Mismatch_ButAuthModeIsSkipXsrf_SoItsAllGood() {
			RunTest(
				request_xsrfHeader: "xsrf",
				request_authorizationHeader: null,
				request_d2lApiCookie: ACCESS_TOKEN,
				accessToken_xsrfClaim: "way different",
				accessToken_validationStatus: ValidationStatus.Success,
				authMode: AuthenticationMode.SkipXsrfValidation,
 				expected_authenticationStatus: AuthenticationStatus.Success,
				expected_nullPrincipal: false
			);
		}

		[Test]
		public void TokenExpired() {
			RunTest(
				request_xsrfHeader: "xsrf",
				request_authorizationHeader: null,
				request_d2lApiCookie: ACCESS_TOKEN,
				accessToken_xsrfClaim: "xsrf",
				accessToken_validationStatus: ValidationStatus.Expired,
				authMode: AuthenticationMode.SkipXsrfValidation,
 				expected_authenticationStatus: AuthenticationStatus.Expired,
				expected_nullPrincipal: true
			);
		}

		private async void RunTest(
			string request_xsrfHeader,
			string request_d2lApiCookie,
			string request_authorizationHeader,
			string accessToken_xsrfClaim,
			ValidationStatus accessToken_validationStatus,
			AuthenticationMode authMode,
			AuthenticationStatus expected_authenticationStatus,
			bool expected_nullPrincipal
		) {
			
			IAccessToken token = AccessTokenMock.Create(
				xsrfClaim: accessToken_xsrfClaim
			).Object;

			var validationResponse = new ValidationResponse(
				accessToken_validationStatus,
				token
			);

			IAccessTokenValidator tokenValidator = AccessTokenValidatorMock.Create(
				accessToken: ACCESS_TOKEN,
				response: validationResponse
			).Object;

			IRequestAuthenticator authenticator = new RequestAuthenticator( tokenValidator );

			var httpRequestMessage = new HttpRequestMessage()
				.WithAuthHeader( request_authorizationHeader )
				.WithXsrfHeader( request_xsrfHeader )
				.WithCookie( RequestValidationConstants.D2L_AUTH_COOKIE_NAME, request_d2lApiCookie );

			AuthenticationResponse authResponse = await authenticator.AuthenticateAsync(
				new Uri( "https://somewhere.something" ),
				httpRequestMessage,
				authMode: authMode
			).SafeAsync();

			Assert.AreEqual( expected_authenticationStatus, authResponse.Status, "Using HttpRequestMessage" );
			Assert.AreEqual( expected_nullPrincipal, authResponse.Principal == null, "Using HttpRequestMessage" );

			HttpRequest httpRequest = HttpRequestMock.Create(
				d2lApiCookieValue: request_d2lApiCookie,
				authorizationHeaderValue: request_authorizationHeader,
				xsrfHeaderValue: request_xsrfHeader
			).Object;

			authResponse = await authenticator.AuthenticateAsync(
				new Uri( "https://somewhere.something" ),
				httpRequest,
				authMode: authMode
			).SafeAsync();
			
			Assert.AreEqual( expected_authenticationStatus, authResponse.Status, "Using HttpRequest" );
			Assert.AreEqual( expected_nullPrincipal, authResponse.Principal == null, "Using HttpRequest" );
		}
		
	}
}
