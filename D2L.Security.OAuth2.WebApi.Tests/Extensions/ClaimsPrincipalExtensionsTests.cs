using System.Linq;
using System.Security.Claims;
using System.Text;
using D2L.Security.OAuth2.Scopes;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Extensions {

	[TestFixture]
	internal sealed class ClaimsPrincipalExtensionsTests {

		[Test]
		public void GetGrantedScopes_Multiple_Success() {
			string[] groups = { "g1", "g2", "g3" };
			string[] resources = { "r1", "r2", "r3" };
			string[] permissions = { "p1", "p2", "p3" };

			StringBuilder builder = new StringBuilder();

			for( int i = 0; i < groups.Length; i++ ) {
				builder.AppendFormat(
					"{0}:{1}:{2} ",
					groups[i],
					resources[i],
					permissions[i]
					);
			}
			// remove trailing space
			builder.Remove( builder.Length - 1, 1 );

			ClaimsPrincipal principal = PrincipalFromScopeClaim( builder.ToString() );
			Scope[] resolvedScopes = principal.GetGrantedScopes().ToArray();

			for( int i = 0; i < resolvedScopes.Length; i++ ) {
				Scope scope = resolvedScopes[i];

				Assert.AreEqual( groups[i], scope.Group );
				Assert.AreEqual( resources[i], scope.Resource );

				Assert.AreEqual( 1, scope.Permissions.Length );
				Assert.AreEqual( permissions[i], scope.Permissions[0] );
			}
		}

		[Test]
		public void GetGrantedScopes_Multiple_ManyPermissions_Success() {
			ClaimsPrincipal principal = PrincipalFromScopeClaim( "dummy:dummy:dummy g:r:p0,p1" );

			Scope[] scopes = principal.GetGrantedScopes().ToArray();
			Assert.AreEqual( 2, scopes.Length );

			Scope actual = scopes[1];
			Assert.AreEqual( "g", actual.Group );
			Assert.AreEqual( "r", actual.Resource );

			string[] actualPermissions = actual.Permissions;
			Assert.AreEqual( 2, actualPermissions.Length );
			Assert.AreEqual( "p0", actualPermissions[0] );
			Assert.AreEqual( "p1", actualPermissions[1] );
		}

		[TestCase( "" )]
		[TestCase( " " )]
		[TestCase( "       " )]
		[TestCase( "a:b: c" )]
		[TestCase( "a:b:   a:b" )]
		[TestCase( ":b: a:b a :b:c :c : " )]
		public void GetGrantedScopes_Multiple_NoneParsed( string scopePattern ) {
			ClaimsPrincipal principal = PrincipalFromScopeClaim( scopePattern );
			Assert.AreEqual( 0, principal.GetGrantedScopes().Count() );
		}

		[TestCase( "a:b:c " )]
		[TestCase( " a:b:c" )]
		public void GetGrantedScopes_ContainsValidScope_ExtraWhiteSpace_ValidScopeParsedSuccessfully( string scopePattern ) {
			ClaimsPrincipal principal = PrincipalFromScopeClaim( scopePattern );
			Scope[] scopes = principal.GetGrantedScopes().ToArray();

			Assert.AreEqual( 1, scopes.Length );
			Assert.AreEqual( "a", scopes[0].Group );
			Assert.AreEqual( "b", scopes[0].Resource );

			Assert.AreEqual( 1, scopes[0].Permissions.Length );
			Assert.AreEqual( "c", scopes[0].Permissions[0] );
		}

		private static ClaimsPrincipal PrincipalFromScopeClaim( string scopeClaimValue ) {
			Claim claim = new Claim( Constants.Claims.SCOPE, scopeClaimValue );
			Claim[] claims = new Claim[] { claim };
			ClaimsIdentity claimsIdentity = new ClaimsIdentity( claims );

			return new ClaimsPrincipal( claimsIdentity );
		}
	}
}