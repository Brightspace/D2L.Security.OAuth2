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
		public async Task ImpersonationToken_Forbidden() {
			string jwt = await TestUtilities
				.GetAccessTokenValidForAMinute( userId: 1234, actualUserId: 1235 )
				.SafeAsync();

			await TestUtilities
				.RunBasicAuthTest( "/authorization/imp", jwt, HttpStatusCode.Forbidden )
				.SafeAsync();
		}
	}
}
