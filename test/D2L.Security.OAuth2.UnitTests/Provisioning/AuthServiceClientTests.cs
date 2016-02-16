using D2L.Security.OAuth2.Provisioning;
using D2L.Security.OAuth2.Provisioning.Default;
using D2L.Security.OAuth2.Scopes;
using D2L.Security.OAuth2.Utilities;
using D2L.Services.Core.Exceptions;
using NUnit.Framework;
using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Provisioning {
	
	[TestFixture]
	[Category( "Unit" )]
	internal sealed class AuthServiceClientTests {
		
		private const string TEST_URI = "http://www.unit.test";
		
		[Test]
		public async void ServiceDown_ExpectServiceException_ConnectionFailure() {
			await RunTest_ExpectServiceException(
				mockClient: MockHttpClient.Create(
					throwsException: new HttpRequestException()
				),
				expectedErrorType: ServiceErrorType.ConnectionFailure
			);
		}
		
		[Test]
		public async void Timeout_ExpectServiceException_Timeout() {
			await RunTest_ExpectServiceException(
				mockClient: MockHttpClient.Create(
					throwsException: new TaskCanceledException()
				),
				expectedErrorType: ServiceErrorType.Timeout
			);
		}
		
		[Test]
		public async void ErrorStatusCode_EmptyResponse_ExpectServiceException_ErrorResponse() {
			await RunTest_ExpectServiceException(
				mockClient: MockHttpClient.Create(
					responseStatus: HttpStatusCode.NotFound,
					responseContent: null
				),
				expectedErrorType: ServiceErrorType.ErrorResponse,
				expectedMessage: "Not Found"
			);
		}
		
		[Test]
		public async void ErrorStatusCode_ValidErrorObject_ExpectServiceException_ErrorResponse() {
			const string ERROR_NAME = "TestError";
			const string ERROR_DETAIL = "Test error details";
			
			await RunTest_ExpectServiceException(
				mockClient: MockHttpClient.Create(
					responseStatus: HttpStatusCode.NotFound,
					responseContent: string.Format(
						"{{ \"error\": \"{0}\", \"error_description\": \"{1}\" }}",
						ERROR_NAME, ERROR_DETAIL
					)
				),
				expectedErrorType: ServiceErrorType.ErrorResponse,
				expectedMessage: string.Concat( ERROR_NAME, ": ", ERROR_DETAIL )
			);
		}
		
		[Test]
		public async void ErrorStatusCodeAndInvalidJson_ExpectServiceException_ErrorResponse() {
			const string AUTH_RESPONSE_CONTENT = "{ \"invalid\": \"format\" }";
			
			await RunTest_ExpectServiceException(
				mockClient: MockHttpClient.Create(
					responseStatus: HttpStatusCode.NotFound,
					responseContent: AUTH_RESPONSE_CONTENT
				),
				expectedErrorType: ServiceErrorType.ErrorResponse,
				expectedMessage: string.Concat( "Not Found: ", AUTH_RESPONSE_CONTENT )
			);
		}
		
		[Test]
		public async void NoContent_ExpectServiceException_ClientError() {
			await RunTest_ExpectServiceException(
				mockClient: MockHttpClient.Create(
					responseStatus: HttpStatusCode.OK,
					responseContent: null
				),
				expectedErrorType: ServiceErrorType.ClientError,
				expectedMessage: AuthServiceClient.EMPTY_RESPONSE_ERROR_MESSAGE
			);
		}
		
		[Test]
		public async void InvalidJson_ExpectServiceException_ClientError() {
			const string AUTH_RESPONSE_CONTENT = "{ \"invalid\": \"format\" }";
			
			await RunTest_ExpectServiceException(
				mockClient: MockHttpClient.Create(
					responseStatus: HttpStatusCode.OK,
					responseContent: AUTH_RESPONSE_CONTENT
				),
				expectedErrorType: ServiceErrorType.ClientError,
				expectedMessage: string.Concat(
					AuthServiceClient.INVALID_JSON_ERROR_MESSAGE_PREFIX,
					AUTH_RESPONSE_CONTENT
				)
			);
		}
		
		[Test]
		public async void ValidResponse_ExpectSuccess() {
			const string TEST_TOKEN = "test-token";
			await RunTest_ExpectSuccess(
				mockClient: MockHttpClient.Create(
					responseStatus: HttpStatusCode.OK,
					responseContent: string.Format( "{{ \"access_token\": \"{0}\" }}", TEST_TOKEN )
				),
				expectedToken: TEST_TOKEN
			);
		}
		
		private async Task RunTest_ExpectServiceException(
			HttpClient mockClient,
			ServiceErrorType expectedErrorType,
			string expectedMessage = null
		) {
			ServiceException exception = null;
			try {
				await RunTestHelper( mockClient );
			} catch( ServiceException ex ) {
				exception = ex;
			}
			
			Assert.IsNotNull( exception );
			Assert.AreEqual( expectedErrorType, exception.ErrorType );
			if( expectedMessage != null ) {
				Assert.AreEqual( expectedMessage, exception.Message );
			}
		}
		
		private async Task RunTest_ExpectSuccess(
			HttpClient mockClient,
			string expectedToken
		) {
			IAccessToken token = await RunTestHelper( mockClient );
			Assert.AreEqual( expectedToken, token.Token );
		}
		
		private async Task<IAccessToken> RunTestHelper( HttpClient mockClient ) {
			IAuthServiceClient client = new AuthServiceClient(
				httpClient: mockClient,
				authEndpoint: new Uri( TEST_URI )
			);
			return await client.ProvisionAccessTokenAsync(
				assertion: string.Empty,
				scopes: new Scope[]{}
			);
		}
		
	}
	
}
