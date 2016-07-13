using System.Collections.Generic;
using FluentAssertions;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Scopes {
	[TestFixture]
	internal sealed class ScopeAuthorizerTests {
		[Test]
		public void NoScopesGranted_AuthorizationShouldBeDenied() {

			var grantedScopes = new Scope[0];
			var requiredScope = new Scope( "g", "r", "p" );

			bool isAuthorized = ScopeAuthorizer.IsAuthorized( grantedScopes, requiredScope );

			isAuthorized.Should().BeFalse();
		}

		[TestCase( "g:r:p", "g:r:p", Description = "Grant exact scope" )]
		[TestCase( "a:b:c,d", "a:b:c,d", Description = "Grant multiple scope exactly" )]
		[TestCase( "a:b:c a:b:d", "a:b:c,d", Description = "Grant multiple scope, validate when compressed" )]
		[TestCase( "a:b:c d:e:f", "d:e:f", Description = "Grant multiple scope uncompressed, validate partial" )]
		[TestCase( "a:b:c,d", "a:b:d,c", Description = "Grant multiple scope exactly, different permission order" )]
		[TestCase( "g:r:p,p2", "g:r:p", Description = "Grant first permission" )]
		[TestCase( "g:r:p,p2", "g:r:p2", Description = "Grant second permission" )]
		[TestCase( "g:r:*", "g:r:p", Description = "Grant all permissions on exact resource in exact group" )]
		[TestCase( "g:*:*", "g:r:p", Description = "Grant all permissions on all resources in exact group" )]
		[TestCase( "*:*:*", "g:r:p", Description = "Grant all permissions on all resources in all groups" )]
		[TestCase( "*:*:p", "g:r:p", Description = "Grant exact permission on all resources in all groups" )]
		[TestCase( "*:r:p", "g:r:p", Description = "Grant exact permission on exact resource in all groups" )]
		public void RequiredScopeIsGranted_AuthorizationShouldBeGranted(
			string grantedScopePattern,
			string requiredScopePattern) {

			var grantedScopes = ParseScopePattern( grantedScopePattern );

			bool isAuthorized = ScopeAuthorizer.IsAuthorized( grantedScopes, Scope.Parse( requiredScopePattern ) );

			isAuthorized.Should().BeTrue();
		}

		[TestCase( "a:b:c a:b:d", "a:b:c,o", Description = "Grant partial uncompressed permissions" )]
		[TestCase( "g:r:p2", "g:r:p", Description = "Permission does not match" )]
		[TestCase( "g:r:p,p2", "g:r:p,p3", Description = "Extra permission is not granted" )]
		[TestCase( "g:r2:p", "g:r:p", Description = "Resource does not match" )]
		[TestCase( "g2:r:p", "g:r:p", Description = "Group does not match" )]
		[TestCase( "*:*:p2", "g:r:p", Description = "Permission does not match - with wildcards" )]
		[TestCase( "*:r2:*", "g:r:p", Description = "Permission does not match - with wildcards" )]
		[TestCase( "g2*:*:*", "g:r:p", Description = "Permission does not match - with wildcards" )]
		public void RequiredScopeIsNotGranted_AuthorizationShouldBeDenied(
			string grantedScopePattern,
			string requiredScopePattern ) {

			var grantedScopes = ParseScopePattern( grantedScopePattern );

			bool isAuthorized = ScopeAuthorizer.IsAuthorized( grantedScopes, Scope.Parse( requiredScopePattern ) );

			isAuthorized.Should().BeFalse();
		}

		private IEnumerable<Scope> ParseScopePattern( string scopePatterns ) {
			foreach( var scopePattern in scopePatterns.Split( ' ' ) ) {
				yield return Scope.Parse( scopePattern );
			}
		}
	}
}
