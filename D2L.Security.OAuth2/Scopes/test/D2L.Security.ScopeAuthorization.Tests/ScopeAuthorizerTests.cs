using FluentAssertions;
using NUnit.Framework;

namespace D2L.Security.ScopeAuthorization.Tests {

	internal sealed class ScopeAuthorizerTests {

		[Test]
		public void NoScopesGranted_AuthorizationShouldBeDenied() {

			var grantedScopes = new Scope[0];
			var requiredScope = new Scope( "g", "r", "p" );

			bool isAuthorized = ScopeAuthorizer.IsAuthorized( grantedScopes, requiredScope );

			isAuthorized.Should().BeFalse();
		}

		[TestCase( "g:r:p", "g:r:p", Description = "Grant exact scope" )]
		[TestCase( "g:r:p,p2", "g:r:p", Description = "Grant extra permissions" )]
		[TestCase( "g:r:*", "g:r:p", Description = "Grant all permissions" )]
		[TestCase( "g:*:*", "g:r:p", Description = "Grant all permissions on all resources" )]
		[TestCase( "*:*:*", "g:r:p", Description = "Grant all permissions on all resources in all groups" )]
		public void RequiredScopeIsGranted_AuthorizationShouldBeGranted(
			string grantedScopePattern,
			string requiredScopePattern) {

			var grantedScopes = new[] { grantedScopePattern.ToScope() };

			bool isAuthorized = ScopeAuthorizer.IsAuthorized( grantedScopes, requiredScopePattern.ToScope() );

			isAuthorized.Should().BeTrue();
		}

		[TestCase( "g:r:p2", "g:r:p", Description = "Permission does not match" )]
		[TestCase( "g:r2:p", "g:r:p", Description = "Resource does not match" )]
		[TestCase( "g2:r:p", "g:r:p", Description = "Group does not match" )]
		public void RequiredScopeIsNotGranted_AuthorizationShouldBeDenied(
			string grantedScopePattern,
			string requiredScopePattern ) {

			var grantedScopes = new[] { grantedScopePattern.ToScope() };

			bool isAuthorized = ScopeAuthorizer.IsAuthorized( grantedScopes, requiredScopePattern.ToScope() );

			isAuthorized.Should().BeFalse();
		}
	
	}

}
