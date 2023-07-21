using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using System.Web;
using D2L.CodeStyle.Annotations;
using D2L.Security.OAuth2.Principal;
using D2L.Security.OAuth2.TestUtilities;
using D2L.Security.OAuth2.TestUtilities.Mocks;
using D2L.Security.OAuth2.Validation.AccessTokens;
using D2L.Security.OAuth2.Validation.Exceptions;
using D2L.Services;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Validation.Request {
	[TestFixture]
	public partial class RequestAuthenticatorTests {
		private const string ACCESS_TOKEN = "some token";

		[Test]
		public async Task TokenInHeader_SuccessCaseAsync() {
			await RunTestAsync(
				request_authorizationHeader: ACCESS_TOKEN
			).ConfigureAwait( false );
		}

		[Test]
		[GenerateSync]
		public async Task NoTokenAsync() {
			await RunTestAsync(
				request_authorizationHeader: string.Empty,
				expectedExceptionType: null,
				expected_principalType: PrincipalType.Anonymous
			).ConfigureAwait( false );
		}

		[Test]
		public async Task TokenExpired() {
			await RunTestAsync(
				request_authorizationHeader: ACCESS_TOKEN,
				expectedExceptionType: typeof( ExpiredTokenException )
			).ConfigureAwait( false );
		}

		[GenerateSync]
		private async Task RunTestAsync(
			string request_authorizationHeader,
			Type expectedExceptionType = null,
			PrincipalType? expected_principalType = null
		) {
			IAccessToken token = AccessTokenMock.Create().Object;

			IAccessTokenValidator tokenValidator = AccessTokenValidatorMock.Create(
				accessToken: ACCESS_TOKEN,
				accessTokenAfterValidation: token,
				expectedExceptionType: expectedExceptionType
			).Object;

			IRequestAuthenticator authenticator = new RequestAuthenticator( tokenValidator );

			var httpRequestMessage = new HttpRequestMessage();
			httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue(
				"Bearer",
				request_authorizationHeader
			);

			ID2LPrincipal principal = null;
			Exception exception = null;
			try {
				principal = await authenticator.AuthenticateAsync(
					httpRequestMessage
					).ConfigureAwait( false );
			} catch( Exception e ) {
				exception = e;
			}

			CheckExpectations(
				principal,
				exception,
				expectedExceptionType,
				expected_principalType );

			exception = null;

			var httpRequest = new HttpRequestMessage();

			httpRequest.Headers.Authorization = new AuthenticationHeaderValue(
				"Bearer",
				request_authorizationHeader
			);

			try {
				principal = await authenticator.AuthenticateAsync(
					httpRequest
				).ConfigureAwait( false );
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
