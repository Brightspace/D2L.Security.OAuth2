using System.Web.Http;
using D2L.Security.OAuth2.Authorization;

namespace D2L.Security.OAuth2.TestWebService.Controllers {
	[DefaultStrictAuthorization]
	public sealed class AuthorizationAttributeTestsController : ApiController {
		[HttpGet]
		[Route("authorization/basic")]
		public void Basic() {
			
		}

		[HttpGet]
		[RequireScope( "foo", "bar", "baz" )]
		[Route("authorization/requirescope")]
		public void ScopeOverride() {
			
		}

		[HttpGet]
		[AllowUsers]
		[Route("authorization/allowusers")]
		public void AllowUsers() {
			
		}

		[HttpGet]
		[NoRequiredScope]
		[Route("authorization/noscope")]
		public void NoScope() {
			
		}

		[HttpGet]
		[OverrideAuthentication]
		[AllowAnonymous]
		[Route("authorization/anonymous")]
		public void Anonymous() {
			
		}
	}
}
