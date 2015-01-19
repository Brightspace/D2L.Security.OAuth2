using System.Collections.Generic;
using D2L.Security.AuthTokenValidation.Default;
using D2L.Security.AuthTokenValidation.Tests.Utilities;
using NUnit.Framework;

namespace D2L.Security.AuthTokenValidation.Tests.Unit.Default {
	
	[TestFixture]
	internal sealed class PrincipalTests {

		[Test]
		public void AssertScope_Valid_Success() {
			HashSet<string> scopes = new HashSet<string>() { "scope1", "scope2" };
			IGenericPrincipal principal = new Principal( 1337, "dummytenantid", "dummyxsrftoken", scopes );
			Assert.DoesNotThrow( () => principal.AssertScope( "scope2" ) );
		}

		[Test]
		public void AssertScope_NullScopes_Fails() {
			AssertFailure( null, "scope" );
		}

		[Test]
		public void AssertScope_EmptyScopes_Fails() {
			AssertFailure( new HashSet<string>(), "scope" );
		}

		[Test]
		public void AssertScope_NotContained_Fails() {
			HashSet<string> scopes = new HashSet<string>() { "scope1" };
			AssertFailure( scopes, "scope2" );
		}

		private void AssertFailure( HashSet<string> scopes, string expectedScope ) {
			IGenericPrincipal principal = new Principal( 1337, "dummytenantid", "dummyxsrftoken", scopes );
			Assertions.Throws( () => principal.AssertScope( expectedScope ) );
		}
	}
}
