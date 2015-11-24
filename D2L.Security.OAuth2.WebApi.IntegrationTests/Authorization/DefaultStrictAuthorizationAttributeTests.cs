using System.Net;
using System.Threading.Tasks;
using NUnit.Framework;
using D2L.Services;

namespace D2L.Security.OAuth2.Authorization {
	// TODO: because the DefaultStrictAuthorizationFilter is itself an authorization filter but if you
	// don't override HandleUnauthorizedRequest then you will get Unauthorized instead of Forbidden. Also
	// any custom logic in the authorization attributes won't run. This is a (at the moment minor) defect
	// that we should fix.
	[TestFixture]
	internal sealed class DefaultStrictAuthorizationAttributeTests {
		[Test]
		public async Task Basic_NoAuthentication_401() {
			await TestUtilities.RunBasicAuthTest( "/authorization/basic", HttpStatusCode.Unauthorized )
				.SafeAsync();
		}

		[Test]
		public async Task Basic_HasSubjectClaim_403() {
			string jwt = await TestUtilities.GetAccessTokenValidForAMinute(
				userId: 123
			).SafeAsync();

			await TestUtilities.RunBasicAuthTest( "/authorization/basic", jwt, HttpStatusCode.Unauthorized ) // TODO: see note at top
				.SafeAsync();
		}

		[Test]
		public async Task Basic_InsufficientScope_403() {
			string jwt = await TestUtilities.GetAccessTokenValidForAMinute(
				scope: "*:*:r"
			).SafeAsync();

			await TestUtilities.RunBasicAuthTest( "/authorization/basic", jwt, HttpStatusCode.Unauthorized ) // TODO: see note at top
				.SafeAsync();
		}

		[Test]
		public async Task Basic_OkJwt_204() {
			string jwt = await TestUtilities.GetAccessTokenValidForAMinute().SafeAsync();

			await TestUtilities.RunBasicAuthTest( "/authorization/basic", jwt, HttpStatusCode.NoContent )
				.SafeAsync();
		}

		[TestCase( "", HttpStatusCode.Forbidden )]
		[TestCase( "foo:bar:notbaz", HttpStatusCode.Forbidden )]
		[TestCase( "foo:bar:baz", HttpStatusCode.NoContent )]
		[TestCase( "foo:*:baz", HttpStatusCode.NoContent )]
		public async Task RequireScope( string scope, HttpStatusCode expectedStatusCode) {
			string jwt = await TestUtilities.GetAccessTokenValidForAMinute(
				scope: scope
			).SafeAsync();

			await TestUtilities.RunBasicAuthTest( "/authorization/requirescope", jwt, expectedStatusCode )
				.SafeAsync();
		}

		[Test]
		public async Task AllowUsers_User_204() {
			string jwt = await TestUtilities.GetAccessTokenValidForAMinute(
				userId: 123	
			).SafeAsync();

			await TestUtilities.RunBasicAuthTest( "/authorization/allowusers", jwt, HttpStatusCode.NoContent )
				.SafeAsync();
		}
		
		[Test]
		public async Task AllowUsers_Service_204() {
			string jwt = await TestUtilities.GetAccessTokenValidForAMinute().SafeAsync();

			await TestUtilities.RunBasicAuthTest( "/authorization/allowusers", jwt, HttpStatusCode.NoContent )
				.SafeAsync();
		}
		
		[TestCase("")]
		[TestCase("*:*:*")]
		[TestCase("foo:*:*")]
		public async Task NoScope_NoMatterWhatScope_204( string scope ) {
			string jwt = await TestUtilities.GetAccessTokenValidForAMinute(
				scope: scope
			).SafeAsync();

			await TestUtilities.RunBasicAuthTest( "/authorization/noscope", jwt, HttpStatusCode.NoContent )
				.SafeAsync();
		}
		[Test]
		public async Task Anonymous_Anything_204() {
			await TestUtilities.RunBasicAuthTest( "/authorization/anonymous", HttpStatusCode.NoContent )
				.SafeAsync();
		}
	}
}
