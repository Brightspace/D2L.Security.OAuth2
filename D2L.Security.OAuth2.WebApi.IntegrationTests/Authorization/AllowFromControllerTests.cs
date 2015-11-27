using System.Net;
using System.Threading.Tasks;
using NUnit.Framework;
using D2L.Services;

namespace D2L.Security.OAuth2.Authorization {
	[TestFixture]
	internal sealed class AllowFromControllerTests {
		private const string SCOPE = "a:b:c";

		[Test]
		public async Task Default_NoAuthentication_403() {
			await TestUtilities.RunBasicAuthTest( "/allowfrom/default", HttpStatusCode.Unauthorized )
				.SafeAsync();
		}

		[Test]
		public async Task Default_UserInvalidScope_401() {
			string jwt = await TestUtilities.GetAccessTokenValidForAMinute(
				userId: 123,
				scope: SCOPE + "foo"
			).SafeAsync();

			await TestUtilities.RunBasicAuthTest( "/allowfrom/default", jwt, HttpStatusCode.Forbidden )
				.SafeAsync();
		}

		[Test]
		public async Task Default_UserValidScope_204() {
			string jwt = await TestUtilities.GetAccessTokenValidForAMinute(
				userId: 123,
				scope: SCOPE
			).SafeAsync();

			await TestUtilities.RunBasicAuthTest( "/allowfrom/default", jwt, HttpStatusCode.NoContent )
				.SafeAsync();
		}

		[TestCase( 0, "wrong:scope:ok", HttpStatusCode.Unauthorized, TestName="A service with the wrong scope" )]
		[TestCase( 0, SCOPE, HttpStatusCode.Unauthorized, TestName= "A service with the right scope" )]
		[TestCase( 123, "wrong:scope:ok", HttpStatusCode.Forbidden, TestName = "A user with the wrong scope" )]
		[TestCase( 123, SCOPE, HttpStatusCode.NoContent, TestName = "A user with the right scope" )]
		public async Task Default_Service_403( long userId, string scope, HttpStatusCode expectedStatusCode ) {
			string jwt = await TestUtilities.GetAccessTokenValidForAMinute(
				userId: userId == 0 ? (long?)null : userId,
				scope: scope
			).SafeAsync();

			await TestUtilities.RunBasicAuthTest( "/allowfrom/default", jwt, expectedStatusCode )
				.SafeAsync();
		}

		[TestCase( 0, "wrong:scope:ok", HttpStatusCode.Forbidden, TestName="A service with wrong scope fails authz" )]
		[TestCase( 0, SCOPE, HttpStatusCode.NoContent, TestName="A service with the right scope succeeds" )]
		[TestCase( 123, "wrong:scope:ok", HttpStatusCode.Forbidden, TestName="A user with the wrong scope fails authz (wrong kind of authn) TODO: does 401 instead of 403 (arguably) due to order of attributes" )]
		[TestCase( 123, SCOPE, HttpStatusCode.Unauthorized, TestName="A user with the right scope fails authz (wrong kind of authn)" )]
		public async Task ServicesOnly_AuthenticationOkCases( long userId, string scope, HttpStatusCode expectedStatusCode ) {
			string jwt = await TestUtilities.GetAccessTokenValidForAMinute(
				userId: userId == 0 ? (long?)null : userId,
				scope: scope
			).SafeAsync();

			await TestUtilities.RunBasicAuthTest( "/allowfrom/servicesonly", jwt, expectedStatusCode )
				.SafeAsync();
		}
	}
}
