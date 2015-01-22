using System;
using System.Collections.Generic;
using System.Security.Principal;
using System.Threading;
using NUnit.Framework;

namespace D2L.Security.WebApiAuthFilter.Tests {

	[TestFixture]
	[Category( "Unit Test" )]
	internal sealed class PrincipalTests {

		private const string IDENTITY = "id";
		private const long USER_ID = 123;
		private const bool IS_BROWSER_USER = true;
		private const string XSRF = "xsrf_token";
		private const string TENANT_ID = "tenant_id";

		private const string IN_SCOPES = "IN_SCOPES";
		private const string NOT_IN_SCOPES = "NOT_IN_SCOPES";

		private const string IN_ROLES = "IN_ROLES";
		private const string NOT_IN_ROLES = "NOT_IN_ROLES";

		private readonly HashSet<string> m_scopes = new HashSet<string> { IN_SCOPES };

		[Test]
		public void Principal_SetProperties_ValuesMatch() {

			IGenericPrincipal principal = new D2LPrincipal();

			Thread.CurrentPrincipal = CreateMockPrincipal();

			Assert.AreEqual( IDENTITY, principal.Identity.Name );
			Assert.AreEqual( USER_ID, principal.UserId );
			Assert.AreEqual( IS_BROWSER_USER, principal.IsBrowserUser );
			Assert.AreEqual( XSRF, principal.XsrfToken );
			Assert.AreEqual( TENANT_ID, principal.TenantId );
			Assert.AreEqual( m_scopes, principal.Scopes );
		}

		[Test]
		public void Principal_HasScope_ResultPassesThrough() {

			IGenericPrincipal principal = new D2LPrincipal();

			Thread.CurrentPrincipal = CreateMockPrincipal();

			Assert.True( principal.HasScope( IN_SCOPES ) );
			Assert.False( principal.HasScope( NOT_IN_SCOPES ) );
		}

		[Test]
		public void Principal_AssertScope_ResultPassesThrough() {

			IGenericPrincipal principal = new D2LPrincipal();

			Thread.CurrentPrincipal = CreateMockPrincipal();

			Assert.DoesNotThrow( () => principal.AssertScope( IN_SCOPES ) );
			Assert.Throws<AuthorizationException>( () => principal.AssertScope( NOT_IN_SCOPES ) );
		}

		[Test]
		public void Principal_IsInRole_ResultPassesThrough() {

			IGenericPrincipal principal = new D2LPrincipal();

			Thread.CurrentPrincipal = CreateMockPrincipal();

			Assert.True( principal.IsInRole( IN_ROLES ) );
			Assert.False( principal.IsInRole( NOT_IN_ROLES ) );
		}

		[Test]
		public void PrincipalProperties_PrincipalNotSet_ExceptionWhenAccessingProperty() {

			IGenericPrincipal principal = new D2LPrincipal();

			Assert.Throws<Exception>( () => { var tenant = principal.TenantId; } );
		}

		private IGenericPrincipal CreateMockPrincipal() {

			Mock<IIdentity> identityMock = new Mock<IIdentity>();
			identityMock.Setup( x => x.Name ).Returns( IDENTITY );

			Mock<IGenericPrincipal> principalMock = new Mock<IGenericPrincipal>();
			principalMock.Setup( x => x.Identity ).Returns( identityMock.Object );
			principalMock.Setup( x => x.UserId ).Returns( USER_ID );
			principalMock.Setup( x => x.IsBrowserUser ).Returns( IS_BROWSER_USER );
			principalMock.Setup( x => x.XsrfToken ).Returns( XSRF );
			principalMock.Setup( x => x.TenantId ).Returns( TENANT_ID );
			principalMock.Setup( x => x.Scopes ).Returns( m_scopes );

			principalMock.Setup( x => x.HasScope( IN_SCOPES ) ).Returns( true );
			principalMock.Setup( x => x.HasScope( NOT_IN_SCOPES ) ).Returns( false );

			principalMock.Setup( x => x.AssertScope( IN_SCOPES ) );
			principalMock.Setup( x => x.AssertScope( NOT_IN_SCOPES ) ).Throws<AuthorizationException>();

			principalMock.Setup( x => x.IsInRole( IN_ROLES ) ).Returns( true );
			principalMock.Setup( x => x.IsInRole( NOT_IN_ROLES ) ).Returns( false );

			return principalMock.Object;
		}
	}
}
