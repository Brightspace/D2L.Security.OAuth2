﻿using System.Net;
using System.Threading.Tasks;
using D2L.Services;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Authorization {
	[TestFixture]
	internal sealed class DefaultAuthorizationAttributeTests {
		[Test]
		public async Task UnspecifiedSpecifiedScope_AnyRequest_500() {
			// Not the most fantastic test because its only asserting on a very
			// overloaded status code but ok.
			await TestUtilities.RunBasicAuthTest( "/authorization/unspecifiedscope", HttpStatusCode.InternalServerError )
				.ConfigureAwait( false );
		}

		[Test]
		public async Task UnspecifiedPrincipalType_AnyRequest_500() {
			// Not the most fantastic test because its only asserting on a very
			// overloaded status code but ok.
			await TestUtilities.RunBasicAuthTest( "/authorization/unspecifiedprincipaltype", HttpStatusCode.InternalServerError )
				.ConfigureAwait( false );
		}


		[Test]
		public async Task Basic_NoAuthentication_403() {
			await TestUtilities.RunBasicAuthTest( "/authorization/basic", HttpStatusCode.Unauthorized )
				.ConfigureAwait( false );
		}

		[TestCase( 0, "", HttpStatusCode.Unauthorized )]
		[TestCase( 0, "foo:bar:baz", HttpStatusCode.Unauthorized )]
		[TestCase( 123, "", HttpStatusCode.Forbidden )]
		[TestCase( 123, "foo:bar:baz", HttpStatusCode.NoContent )]
		[TestCase( 123, "foo:*:baz", HttpStatusCode.NoContent )]
		public async Task Basic_DifferentTokens(
			long userId,
			string scope,
			HttpStatusCode expectedStatusCode
		) {
			string jwt = await TestUtilities.GetAccessTokenValidForAMinute(
				userId: userId == 0 ? ( long? )null : userId,
				scope: scope
			).ConfigureAwait( false );

			await TestUtilities.RunBasicAuthTest( "/authorization/basic", jwt, expectedStatusCode )
				.ConfigureAwait( false );
		}

		[TestCase( "" )]
		[TestCase( "*:*:*" )]
		[TestCase( "foo:*:*" )]
		public async Task NoScope_NoMatterWhatScope_204( string scope ) {
			string jwt = await TestUtilities.GetAccessTokenValidForAMinute(
				scope: scope
			).ConfigureAwait( false );

			await TestUtilities.RunBasicAuthTest( "/authorization/noscope", jwt, HttpStatusCode.NoContent )
				.ConfigureAwait( false );
		}

		[Test]
		public async Task Anonymous_NoToken_204() {
			await TestUtilities.RunBasicAuthTest( "/authorization/anonymous", HttpStatusCode.NoContent )
				.ConfigureAwait( false );
		}

		[TestCase( "" )]
		[TestCase( "*:*:*" )]
		[TestCase( "foo:bar:baz" )]
		public async Task Anonymous_User_204( string scope ) {
			string jwt = await TestUtilities.GetAccessTokenValidForAMinute(
				userId: 12312,
				scope: scope
			).ConfigureAwait( false );

			await TestUtilities.RunBasicAuthTest( "/authorization/anonymous", jwt, HttpStatusCode.NoContent )
				.ConfigureAwait( false );
		}

		[TestCase( "" )]
		[TestCase( "*:*:*" )]
		[TestCase( "foo:bar:baz" )]
		public async Task Anonymous_Service_204( string scope ) {
			string jwt = await TestUtilities.GetAccessTokenValidForAMinute(
				scope: scope
			).ConfigureAwait( false );

			await TestUtilities.RunBasicAuthTest( "/authorization/anonymous", jwt, HttpStatusCode.NoContent )
				.ConfigureAwait( false );
		}
	}
}
