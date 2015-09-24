using System.Collections.ObjectModel;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Web.Http;
using System.Web.Http.Controllers;
using FluentAssertions;
using Moq;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Scopes {
	internal sealed class ScopeAuthorizeAttributeTests {
		[Test]
		public void PrincipalNotSet_AuthorizationShouldBeDenied() {

			var actionContext = CreateActionContextWithPrinciapl( null );

			var attr = new ScopeAuthorizeAttribute( "g", "r", "p" );
			attr.OnAuthorization( actionContext );

			AssertIsNotAuthorized( actionContext.Response );
		}

		[Test]
		public void NoScopesGranted_AuthorizationShouldBeDenied() {

			var principal = CreatePrinciaplWithScopeClaim( null );
			var actionContext = CreateActionContextWithPrinciapl( principal );

			var attr = new ScopeAuthorizeAttribute( "g", "r", "p" );
			attr.OnAuthorization( actionContext );

			AssertIsNotAuthorized( actionContext.Response );
		}

		[Test]
		public void RequiredScopeIsNotGranted_AuthorizationShouldBeDenied() {

			var principal = CreatePrinciaplWithScopeClaim( "g:r:x" );
			var actionContext = CreateActionContextWithPrinciapl( principal );

			var attr = new ScopeAuthorizeAttribute( "g", "r", "p" );
			attr.OnAuthorization( actionContext );

			AssertIsNotAuthorized( actionContext.Response );
		}

		[Test]
		public void RequiredScopeIsGranted_AuthorizationShouldBeGranted() {

			var principal = CreatePrinciaplWithScopeClaim( "g:r:p" );
			var actionContext = CreateActionContextWithPrinciapl( principal );

			var attr = new ScopeAuthorizeAttribute( "g", "r", "p" );
			attr.OnAuthorization( actionContext );

			AssertIsAuthorized( actionContext.Response );
		}

		#region Helpers

		private static HttpActionContext CreateActionContextWithPrinciapl( ClaimsPrincipal princiapl ) {

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

			var actionContext = ContextUtil.CreateActionContext( controllerContext, actionDescriptorMock.Object );

			actionContext.ControllerContext.RequestContext.Principal = princiapl;

			return actionContext;
		}

		private static ClaimsPrincipal CreatePrinciaplWithScopeClaim( string scopePattern ) {

			var claims = ( scopePattern == null )
				? Enumerable.Empty<Claim>()
				: new[] { new Claim( Constants.ClaimTypes.Scope, scopePattern ) };
			var identity = new ClaimsIdentity( claims );
			var principal = new ClaimsPrincipal( identity );

			return principal;
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

		#endregion

	}

}