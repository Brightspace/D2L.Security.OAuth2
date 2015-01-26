using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using D2L.Security.RequestAuthentication.Core;
using D2L.Security.RequestAuthentication.Core.Default;
using NUnit.Framework;

namespace D2L.Security.RequestAuthentication.Tests.Unit.Core.Default {
	
	[TestFixture]
	internal sealed class CoreAuthenticatorTests {

		[TestCase( null, null )]
		[TestCase( null, "" )]
		[TestCase( "", null )]
		[TestCase( "", "" )]
		public void Authenticate_NullOrEmptyCookieAndBearerToken_Anonymous( string cookie, string bearerToken ) {
			ICoreAuthenticator authenticator = new CoreAuthenticator( null, true );
			ID2LPrincipal principal;
			
			AuthenticationResult result = authenticator.Authenticate( cookie, "dummyxsrf", bearerToken, out principal );
			Assert.AreEqual( AuthenticationResult.Anonymous, result );
		}

		[Test]
		public void Authenticate_TokenInBothCookieAndBearerToken_Conflict() {
			ICoreAuthenticator authenticator = new CoreAuthenticator( null, true );
			ID2LPrincipal principal;

			AuthenticationResult result = authenticator.Authenticate( "dummycookie", "dummyxsrftoken", "dummybearer", out principal );
			Assert.AreEqual( AuthenticationResult.LocationConflict, result );
		}
	}
}
