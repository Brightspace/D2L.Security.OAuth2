using D2L.Security.OAuth2.Provisioning;
using D2L.Security.OAuth2.Provisioning.Default;
using D2L.Security.OAuth2.Scopes;
using D2L.Security.OAuth2.Tests.Utilities;
using D2L.Services.Core.Exceptions;
using NUnit.Framework;
using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Tests.Unit.Provisioning {
	
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
		public async void ErrorStatusCode_ExpectServiceException_ErrorResponse() {
			await RunTest_ExpectServiceException(
				mockClient: MockHttpClient.Create(
					responseStatus: HttpStatusCode.NotFound
				),
				expectedErrorType: ServiceErrorType.ErrorResponse
			);
		}
		
		[Test]
		public async void NoContent_ExpectServiceException_ClientError() {
			await RunTest_ExpectServiceException(
				mockClient: MockHttpClient.Create(
					responseStatus: HttpStatusCode.OK,
					responseContent: null
				),
				expectedErrorType: ServiceErrorType.ClientError
			);
		}
		
		[Test]
		public async void InvalidJson_ExpectServiceException_ClientError() {
			await RunTest_ExpectServiceException(
				mockClient: MockHttpClient.Create(
					responseStatus: HttpStatusCode.OK,
					responseContent: "{ invalid: \"format\" }"
				),
				expectedErrorType: ServiceErrorType.ClientError
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
			ServiceErrorType expectedErrorType
		) {
			ServiceException exception = null;
			try {
				await RunTestHelper( mockClient );
			} catch( ServiceException ex ) {
				exception = ex;
			}
			
			Assert.IsNotNull( exception );
			Assert.AreEqual( expectedErrorType, exception.ErrorType );
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
