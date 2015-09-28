using System.Collections.ObjectModel;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading;
using System.Web.Http;
using System.Web.Http.Controllers;
using D2L.Security.OAuth2.Principal;
using FluentAssertions;
using Moq;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Scopes {
	internal sealed class ScopeAuthorizeAttributeTests {
		private HttpActionContext m_actionContext;

		[SetUp]
		public void SetUp() {
			var allowAnonymousAttributeCollection =
				new Collection<AllowAnonymousAttribute>( Enumerable.Empty<AllowAnonymousAttribute>().ToList() );

			var controllerDescriptorMock = new Mock<HttpControllerDescriptor> { CallBase = true };
			controllerDescriptorMock
				.Setup( cd => cd.GetCustomAttributes<AllowAnonymousAttribute>() )
				.Returns( allowAnonymousAttributeCollection );

			var controllerContext = new Mock<HttpControllerContext> { CallBase = true }.Object;
			controllerContext.ControllerDescriptor = controllerDescriptorMock.Object;
			controllerContext.Request = new HttpRequestMessage();

			var actionDescriptorMock = new Mock<HttpActionDescriptor> { CallBase = true };
			actionDescriptorMock
				.Setup( ad => ad.GetCustomAttributes<AllowAnonymousAttribute>() )
				.Returns( allowAnonymousAttributeCollection );

			m_actionContext = ContextUtil.CreateActionContext( controllerContext, actionDescriptorMock.Object );
		}

		[Test]
		public void PrincipalNotSet_AuthorizationShouldBeDenied() {
			var attr = new ScopeAuthorizeAttribute( "g", "r", "p" );
			attr.OnAuthorization( m_actionContext );

			AssertIsNotAuthorized( m_actionContext.Response );
		}

		[Test]
		public void NoScopesGranted_AuthorizationShouldBeDenied() {
			SetupPrincipal();

			var attr = new ScopeAuthorizeAttribute( "g", "r", "p" );
			attr.OnAuthorization( m_actionContext );

			AssertIsNotAuthorized( m_actionContext.Response );
		}

		[Test]
		public void RequiredScopeIsNotGranted_AuthorizationShouldBeDenied() {
			SetupPrincipal( "g:r:x" );

			var attr = new ScopeAuthorizeAttribute( "g", "r", "p" );
			attr.OnAuthorization( m_actionContext );

			AssertIsNotAuthorized( m_actionContext.Response );
		}

		[Test]
		public void RequiredScopeIsGranted_AuthorizationShouldBeGranted() {
			SetupPrincipal( "g:r:p" );

			var attr = new ScopeAuthorizeAttribute( "g", "r", "p" );
			attr.OnAuthorization( m_actionContext );

			AssertIsAuthorized( m_actionContext.Response );
		}

		[Test]
		public void RequiredScopeIsGranted_PrincipalOnActionContect_AuthorizationShouldBeGranted() {
			SetupPrincipal( "g:r:p", setOnActionContextInstead: true );

			var attr = new ScopeAuthorizeAttribute( "g", "r", "p" );
			attr.OnAuthorization( m_actionContext );

			AssertIsAuthorized( m_actionContext.Response );
		}

		private void SetupPrincipal( string scope = null, bool setOnActionContextInstead = false) {
			var d2lPrincipal = new Mock<ID2LPrincipal>( MockBehavior.Strict );
			d2lPrincipal.Setup( p => p.Scopes ).Returns( scope == null ? new Scope[] { } : new[] { Scope.Parse( scope ) } );
			var principal = new D2LPrincipalAdapter( d2lPrincipal.Object);

			if( setOnActionContextInstead ) {
				m_actionContext.RequestContext.Principal = principal;
			} else {
				Thread.CurrentPrincipal = principal;
			}
		}

		private static void AssertIsAuthorized( HttpResponseMessage response ) {
			// response should be null (i.e. not short-circuited with a 403 by attribute)
			response.Should().BeNull();
		}

		private static void AssertIsNotAuthorized( HttpResponseMessage response ) {
			// response should be 403
			response.Should().NotBeNull();
			response.StatusCode.Should().Be( HttpStatusCode.Forbidden );
		}
	}

}