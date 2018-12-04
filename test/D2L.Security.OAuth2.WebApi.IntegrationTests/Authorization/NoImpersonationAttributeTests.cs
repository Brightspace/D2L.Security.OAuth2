using System.Net;
using System.Threading.Tasks;
using D2L.Services;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Authorization {
	[TestFixture]
	internal sealed class NoImpersonationAttributeTests {
		[Test]
		public async Task ServiceToken_OK() {
			string jwt = await TestUtilities
				.GetAccessTokenValidForAMinute()
				.SafeAsync();

			await TestUtilities
				.RunBasicAuthTest( "/authorization/imp", jwt, HttpStatusCode.NoContent )
				.SafeAsync();
		}

		[Test]
		public async Task UserToken_OK() {
			string jwt = await TestUtilities
				.GetAccessTokenValidForAMinute( userId: 1234 )
				.SafeAsync();

			await TestUtilities
				.RunBasicAuthTest( "/authorization/imp", jwt, HttpStatusCode.NoContent )
				.SafeAsync();
		}

		[Test]
		public async Task ImpersonationToken_Unauthorized() {
			string jwt = await TestUtilities
				.GetAccessTokenValidForAMinute( userId: 1234, actualUserId: 1235 )
				.SafeAsync();

			var response = await TestUtilities
				.RunBasicAuthTest<OAuth2ErrorResponse>( "/authorization/imp", jwt, HttpStatusCode.Unauthorized )
				.SafeAsync();

			string expectedError = "invalid_token";
			string expectedErrorDescription = "This API is not usable while impersonating. This error message indicates a bug in the client application which is responsible for knowing this.";

			Assert.AreEqual( expectedError, response.Body.Error );
			Assert.AreEqual( expectedErrorDescription, response.Body.ErrorDescription );

			string challengeHeader = response.Headers.WwwAuthenticate.ToString();
			StringAssert.Contains( expectedError, challengeHeader );
			StringAssert.Contains( expectedErrorDescription, challengeHeader );
		}
	}
}
