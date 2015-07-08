using System;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web;
using D2L.Security.OAuth2.Principal;
using D2L.Security.OAuth2.Tests.Utilities;
using D2L.Security.OAuth2.Tests.Utilities.Mocks;
using D2L.Security.OAuth2.Validation.AccessTokens;
using D2L.Security.OAuth2.Validation.Request;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Tests.Unit.Validation.Request {
	
	[TestFixture]
	[Category( "Unit" )]
	public class RequestAuthenticatorTests {

		private const string ACCESS_TOKEN = "some token";
		
		[Test]
		public async Task TokenInHeader_SuccessCase() {
			await RunTest(
				request_xsrfHeader: "xsrf",
				request_authorizationHeader: ACCESS_TOKEN,
				request_d2lApiCookie: null,
				accessToken_xsrfClaim: "xsrf",
				accessToken_validationStatus: ValidationStatus.Success,
				authMode: AuthenticationMode.Full,
 				expected_authenticationStatus: AuthenticationStatus.Success,
				expected_nullPrincipal: false
			).SafeAsync();
		}

		[Test]
		public async Task TokenInCookie_SuccessCase() {
			await RunTest(
				request_xsrfHeader: "xsrf",
				request_authorizationHeader: null,
				request_d2lApiCookie: ACCESS_TOKEN,
				accessToken_xsrfClaim: "xsrf",
				accessToken_validationStatus: ValidationStatus.Success,
				authMode: AuthenticationMode.Full,
 				expected_authenticationStatus: AuthenticationStatus.Success,
				expected_nullPrincipal: false
			).SafeAsync();
		}

		[Test]
		public async Task TokenInHeaderAndCookie_ThatsaNoNo() {
			await RunTest(
				request_xsrfHeader: "xsrf",
				request_authorizationHeader: ACCESS_TOKEN,
				request_d2lApiCookie: ACCESS_TOKEN,
				accessToken_xsrfClaim: "xsrf",
				accessToken_validationStatus: ValidationStatus.Success,
				authMode: AuthenticationMode.Full,
 				expected_authenticationStatus: AuthenticationStatus.LocationConflict,
				expected_nullPrincipal: true
			).SafeAsync();
		}

		[Test]
		public async Task NoToken() {
			await RunTest(
				request_xsrfHeader: "xsrf",
				request_authorizationHeader: string.Empty,
				request_d2lApiCookie: string.Empty,
				accessToken_xsrfClaim: "xsrf",
				accessToken_validationStatus: ValidationStatus.Success,
				authMode: AuthenticationMode.Full,
 				expected_authenticationStatus: AuthenticationStatus.Anonymous,
				expected_nullPrincipal: false,
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
				accessToken_validationStatus: ValidationStatus.Success,
				authMode: AuthenticationMode.Full,
 				expected_authenticationStatus: AuthenticationStatus.XsrfMismatch,
				expected_nullPrincipal: true
			).SafeAsync();
		}

		[Test]
		public async Task Xsrf_Mismatch_ButAuthModeIsSkipXsrf_SoItsAllGood() {
			await RunTest(
				request_xsrfHeader: "xsrf",
				request_authorizationHeader: null,
				request_d2lApiCookie: ACCESS_TOKEN,
				accessToken_xsrfClaim: "way different",
				accessToken_validationStatus: ValidationStatus.Success,
				authMode: AuthenticationMode.SkipXsrfValidation,
 				expected_authenticationStatus: AuthenticationStatus.Success,
				expected_nullPrincipal: false
			).SafeAsync();
		}

		[Test]
		public async Task TokenExpired() {
			await RunTest(
				request_xsrfHeader: "xsrf",
				request_authorizationHeader: null,
				request_d2lApiCookie: ACCESS_TOKEN,
				accessToken_xsrfClaim: "xsrf",
				accessToken_validationStatus: ValidationStatus.Expired,
				authMode: AuthenticationMode.SkipXsrfValidation,
 				expected_authenticationStatus: AuthenticationStatus.Expired,
				expected_nullPrincipal: true
			).SafeAsync();
		}

		private async Task RunTest(
			string request_xsrfHeader,
			string request_d2lApiCookie,
			string request_authorizationHeader,
			string accessToken_xsrfClaim,
			ValidationStatus accessToken_validationStatus,
			AuthenticationMode authMode,
			AuthenticationStatus expected_authenticationStatus,
			bool expected_nullPrincipal,
			PrincipalType? expected_principalType = null
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
				httpRequestMessage,
				authMode: authMode
			).SafeAsync();
			
			CheckExpectations(
				authResponse,
				expected_authenticationStatus,
				expected_nullPrincipal,
				expected_principalType );

			HttpRequest httpRequest = RequestBuilder.Create()
				.WithAuthHeader( request_authorizationHeader )
				.WithXsrfHeader( request_xsrfHeader )
				.WithCookie( RequestValidationConstants.D2L_AUTH_COOKIE_NAME, request_d2lApiCookie );

			authResponse = await authenticator.AuthenticateAsync(
				httpRequest,
				authMode: authMode
			).SafeAsync();
			
			CheckExpectations(
				authResponse,
				expected_authenticationStatus,
				expected_nullPrincipal,
				expected_principalType );

			Assert.AreEqual( expected_authenticationStatus, authResponse.Status, "Using HttpRequest" );
			Assert.AreEqual( expected_nullPrincipal, authResponse.Principal == null, "Using HttpRequest" );
		}

		private void CheckExpectations(
			AuthenticationResponse authResponse,
			AuthenticationStatus expected_authenticationStatus,
			bool expected_nullPrincipal,
			PrincipalType? expected_principalType
		) {

			Assert.AreEqual( expected_authenticationStatus, authResponse.Status, "Using HttpRequest" );
			Assert.AreEqual( expected_nullPrincipal, authResponse.Principal == null, "Using HttpRequest" );

			if( expected_principalType.HasValue ) {
				Assert.AreEqual( expected_principalType, authResponse.Principal.Type );
			}
		}
	}
}
