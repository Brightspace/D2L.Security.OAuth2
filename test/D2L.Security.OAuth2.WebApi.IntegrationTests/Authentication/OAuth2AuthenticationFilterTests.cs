using System.Threading.Tasks;
using NUnit.Framework;
using D2L.Services;
using System.Net;
using System.Net.Http;
using System;
using System.Net.Http.Headers;

namespace D2L.Security.OAuth2.Authentication {
	[TestFixture]
	internal sealed class OAuth2AuthenticationFilterTests {
		[Test]
		public async Task Basic_NoAuthAtAll_204() {
			await TestUtilities.RunBasicAuthTest( "/authentication/basic", HttpStatusCode.NoContent )
				.SafeAsync();
		}

		[Test]
		public async Task Basic_GarbageJwt_401() {
			const string GARBAGE_JWT = "foo";

			await TestUtilities.RunBasicAuthTest( "/authentication/basic", GARBAGE_JWT, HttpStatusCode.Unauthorized )
				.SafeAsync();
		}

		[Test]
		public async Task Basic_ExpiredJwt_401() {
			string dayOldJwt = await TestUtilities
				.GetAccessTokenValidForAMinute(
					issuedAtTime: DateTime.UtcNow - TimeSpan.FromDays( 1 )
				).SafeAsync();

			await TestUtilities.RunBasicAuthTest( "/authentication/basic", dayOldJwt, HttpStatusCode.Unauthorized )
				.SafeAsync();
		}

		[Test]
		public async Task Basic_ValidJwt_204() {
			string validJwt = await TestUtilities
				.GetAccessTokenValidForAMinute()
				.SafeAsync();

			await TestUtilities.RunBasicAuthTest( "/authentication/basic", validJwt, HttpStatusCode.NoContent )
				.SafeAsync();
		}

		[Test]
		public async Task Anonymous_NoAuth_204() {
			await TestUtilities.RunBasicAuthTest( "/authentication/anonymous", HttpStatusCode.NoContent )
				.SafeAsync();
		}
	}
}
