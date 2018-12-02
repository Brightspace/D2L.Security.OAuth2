using System.Net;
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
		public async Task ServiceToken_Forbidden() {
			string jwt = await TestUtilities
				.GetAccessTokenValidForAMinute( userId: null )
				.SafeAsync();

			string body = await TestUtilities
				.RunBasicAuthTest( RequireClaimAttributeTestsController.ROUTE, jwt, HttpStatusCode.Forbidden )
				.SafeAsync();

			StringAssert.Contains( Constants.Claims.USER_ID, body );
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