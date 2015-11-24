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
		[AllowUsersAndServices]
		[NoRequiredScope] 
		[Route("authorization/allowusers")]
		public void AllowUsers() {
			// This route uses the [NoRequiredScope] attribute to make sure that it 401s
			// for anon users inside [AllowUsersAndServices]... otherwise it might 401
			// inside [RequiredScope(...)] depending on the order inside
			// DefaultStrictAuthorizationAttribute.
		}

		[HttpGet]
		[NoRequiredScope]
		[Route("authorization/noscope")]
		public void NoScope() {
			
		}

		[HttpGet]
		[AllowAnonymous]
		[Route("authorization/anonymous")]
		public void Anonymous() {
			
		}
	}
}
