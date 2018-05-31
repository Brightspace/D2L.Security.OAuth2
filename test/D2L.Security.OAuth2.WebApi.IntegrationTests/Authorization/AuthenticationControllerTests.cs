using System.Net;
using System.Threading.Tasks;
using D2L.Services;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Authorization {
	[TestFixture]
	internal sealed class AuthenticationControllerTests {
		private const string SCOPE = "a:b:c";

		[Test]
		public async Task Default_NoAuthentication_403() {
			await TestUtilities.RunBasicAuthTest( "/allowfrom/default", HttpStatusCode.Unauthorized )
				.SafeAsync();
		}

		[TestCase( "default", 0, "wrong:scope:ok", HttpStatusCode.Unauthorized, TestName = "default, a service with the wrong scope fails" )]
		[TestCase( "default", 0, SCOPE, HttpStatusCode.Unauthorized, TestName = "default, a service with the right scope fails" )]
		[TestCase( "default", 123, "wrong:scope:ok", HttpStatusCode.Forbidden, TestName = "default, a user with the wrong scope fails" )]
		[TestCase( "default", 123, SCOPE, HttpStatusCode.NoContent, TestName = "default, a user with the right scope passes" )]
		[TestCase( "servicesonly", 0, "wrong:scope:ok", HttpStatusCode.Forbidden, TestName = "ServicesOnly, a service with wrong scope fails" )]
		[TestCase( "servicesonly", 0, SCOPE, HttpStatusCode.NoContent, TestName = "ServicesOnly, a service with the right scope passes" )]
		[TestCase( "servicesonly", 123, "wrong:scope:ok", HttpStatusCode.Unauthorized, TestName = "ServicesOnly, a user with the wrong scope fails" )]
		[TestCase( "servicesonly", 123, SCOPE, HttpStatusCode.Unauthorized, TestName = "ServicesOnly, a user with the right scope fails" )]
		[TestCase( "usersorservices", 0, "wrong:scope:ok", HttpStatusCode.Forbidden, TestName = "Users/services route, a service with wrong scope fails" )]
		[TestCase( "usersorservices", 0, SCOPE, HttpStatusCode.NoContent, TestName = "Users/services route, service passes" )]
		[TestCase( "usersorservices", 123, "wrong:scope:ok", HttpStatusCode.Forbidden, TestName = "Users/services route, a user with the wrong scope fails authz" )]
		[TestCase( "usersorservices", 123, SCOPE, HttpStatusCode.NoContent, TestName = "Users/services route, user passes" )]
		public async Task AuthenticatedTests( string route, long userId, string scope, HttpStatusCode expectedStatusCode ) {
			string jwt = await TestUtilities.GetAccessTokenValidForAMinute(
				userId: userId == 0 ? ( long? )null : userId,
				scope: scope
			).SafeAsync();

			await TestUtilities.RunBasicAuthTest( "/allowfrom/" + route, jwt, expectedStatusCode )
				.SafeAsync();
		}
	}
}
