﻿using System.Net;
using System.Threading.Tasks;
using D2L.Security.OAuth2.TestWebService.Controllers;
using D2L.Services;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Authorization {
	[TestFixture]
	internal sealed class RequireClaimAttributeTests {
		[Test]
		public async Task NoToken_Unauthorized() {
			await TestUtilities
				.RunBasicAuthTest( RequireClaimAttributeTestsController.ROUTE, HttpStatusCode.Unauthorized )
				.SafeAsync();
		}

		[Test]
		public async Task ServiceToken_Unauthorized() {
			string jwt = await TestUtilities
				.GetAccessTokenValidForAMinute( userId: null )
				.SafeAsync();

			var response = await TestUtilities
				.RunBasicAuthTest<OAuth2ErrorResponse>( RequireClaimAttributeTestsController.ROUTE, jwt, HttpStatusCode.Unauthorized )
				.SafeAsync();

			string expectedError = "invalid_token";
			string expectedErrorDescription = $"Missing claim: '{ Constants.Claims.USER_ID }'";

			Assert.AreEqual( expectedError, response.Body.Error );
			Assert.AreEqual( expectedErrorDescription, response.Body.ErrorDescription );

			string challengeHeader = response.Headers.WwwAuthenticate.ToString();
			StringAssert.Contains( expectedError, challengeHeader );
			StringAssert.Contains( expectedErrorDescription, challengeHeader );
		}

		[Test]
		public async Task UserToken_OK() {
			string jwt = await TestUtilities
				.GetAccessTokenValidForAMinute( userId: 123 )
				.SafeAsync();

			await TestUtilities
				.RunBasicAuthTest( RequireClaimAttributeTestsController.ROUTE, jwt, HttpStatusCode.NoContent )
				.SafeAsync();
		}
	}
}