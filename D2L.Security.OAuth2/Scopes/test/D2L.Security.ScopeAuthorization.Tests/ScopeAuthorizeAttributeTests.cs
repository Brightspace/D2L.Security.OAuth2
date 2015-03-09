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

namespace D2L.Security.ScopeAuthorization.Tests {

	internal sealed class ScopeAuthorizeAttributeTests {

		private static readonly Collection<AllowAnonymousAttribute> AllowAnonymousAttributeCollection =
			new Collection<AllowAnonymousAttribute>( Enumerable.Empty<AllowAnonymousAttribute>().ToList() );

		private readonly HttpActionContext m_actionContext;

		public ScopeAuthorizeAttributeTests() {

			var controllerDescriptorMock = new Mock<HttpControllerDescriptor> { CallBase = true };
			controllerDescriptorMock
				.Setup( cd => cd.GetCustomAttributes<AllowAnonymousAttribute>() )
				.Returns( AllowAnonymousAttributeCollection );

			var controllerContext = new Mock<HttpControllerContext> { CallBase = true }.Object;
			controllerContext.ControllerDescriptor = controllerDescriptorMock.Object;
			controllerContext.Request = new HttpRequestMessage();

			var actionDescriptorMock = new Mock<HttpActionDescriptor> { CallBase = true };
			actionDescriptorMock
				.Setup( ad => ad.GetCustomAttributes<AllowAnonymousAttribute>() )
				.Returns( AllowAnonymousAttributeCollection );

			m_actionContext = ContextUtil.CreateActionContext( controllerContext, actionDescriptorMock.Object );
		}

		[Test]
		public void PrincipalNotSet_AuthorizationShouldBeDenied() {

			m_actionContext.ControllerContext.RequestContext.Principal = null;

			var attr = new ScopeAuthorizeAttribute( "g", "r", "p" );
			attr.OnAuthorization( m_actionContext );

			// response should be 403
			m_actionContext.Response.Should().NotBeNull();
			m_actionContext.Response.StatusCode.Should().Be( HttpStatusCode.Forbidden );
		}

		[Test]
		public void NoScopesGranted_AuthorizationShouldBeDenied() {

			// create claims principal
			var claims = Enumerable.Empty<Claim>();
			var identity = new ClaimsIdentity( claims );
			var principal = new ClaimsPrincipal( identity );
			// assign principal to request context
			m_actionContext.ControllerContext.RequestContext.Principal = principal;

			var attr = new ScopeAuthorizeAttribute( "g", "r", "p" );
			attr.OnAuthorization( m_actionContext );

			// response should be 403
			m_actionContext.Response.Should().NotBeNull();
			m_actionContext.Response.StatusCode.Should().Be( HttpStatusCode.Forbidden );
		}

		[Test]
		public void RequiredScopeIsNotGranted_AuthorizationShouldBeDenied() {

			// create claims principal
			var claims = new[] { new Claim( Constants.ClaimTypes.Scope, "g:r:x" ) };
			var identity = new ClaimsIdentity( claims );
			var principal = new ClaimsPrincipal( identity );
			// assign principal to request context
			m_actionContext.ControllerContext.RequestContext.Principal = principal;

			var attr = new ScopeAuthorizeAttribute( "g", "r", "p" );
			attr.OnAuthorization( m_actionContext );

			// response should be 403
			m_actionContext.Response.Should().NotBeNull();
			m_actionContext.Response.StatusCode.Should().Be( HttpStatusCode.Forbidden );
		}

		[Test]
		public void RequiredScopeIsGranted_AuthorizationShouldBeGranted() {

			// create claims principal
			var claims = new[] { new Claim( Constants.ClaimTypes.Scope, "g:r:p" ) };
			var identity = new ClaimsIdentity( claims );
			var principal = new ClaimsPrincipal( identity );
			// assign principal to request context
			m_actionContext.ControllerContext.RequestContext.Principal = principal;

			var attr = new ScopeAuthorizeAttribute( "g", "r", "p" );
			attr.OnAuthorization( m_actionContext );

			// response should be null (i.e. not short-circuited with a 403 by attribute)
			m_actionContext.Response.Should().BeNull();
		}

	}

}
