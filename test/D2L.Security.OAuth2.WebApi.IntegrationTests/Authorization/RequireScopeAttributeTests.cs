using System.Net;
using System.Threading.Tasks;
using D2L.Security.OAuth2.TestWebService.Controllers;
using D2L.Services;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Authorization {
	[TestFixture]
	internal sealed class RequireScopeAttributeTests {

		[Test]
		public async Task Token_Scope_XYZ_403() {
			string jwt = await TestUtilities
				.GetAccessTokenValidForAMinute( userId: 123, scope: "x:y:z" )
				.SafeAsync();

			var response = await TestUtilities
				.RunBasicAuthTest<OAuth2ErrorResponse>( RequireScopeAttributeTestsController.ROUTE, jwt, HttpStatusCode.Forbidden )
				.SafeAsync();

			string expectedError = "insufficient_scope";
			string expectedErrorDescription = $"Required scope: 'a:b:c'";

			Assert.AreEqual( expectedError, response.Body.Error );
			Assert.AreEqual( expectedErrorDescription, response.Body.ErrorDescription );

			string challengeHeader = response.Headers.WwwAuthenticate.ToString();
			StringAssert.Contains( expectedError, challengeHeader );
			StringAssert.Contains( expectedErrorDescription, challengeHeader );
		}

		[Test]
		public async Task Token_Scope_ABC_Okay() {
			string jwt = await TestUtilities
				.GetAccessTokenValidForAMinute( userId: 123, scope: "a:b:c" )
				.SafeAsync();

			await TestUtilities
				.RunBasicAuthTest( RequireScopeAttributeTestsController.ROUTE, jwt, HttpStatusCode.NoContent )
				.SafeAsync();
		}
	}
}