using System.Web.Http;
using D2L.Security.OAuth2.Authorization;

namespace D2L.Security.OAuth2.TestWebService.Controllers {
	[DefaultAuthorization]
	public sealed class AuthorizationAttributeTestsController : ApiController {
		[HttpGet]
		[Route("authorization/unspecifiedscope")]
		public void UnspecifiedScope() {
			
		}

		[HttpGet]
		[RequireScope("foo","bar","baz")]
		[Route("authorization/basic")]
		public void Basic() {
			
		}

		[HttpGet]
		[AllowUsersAndServices]
		[NoRequiredScope] 
		[Route("authorization/allowusers")]
		public void AllowUsers() {
			// This route uses the [NoRequiredScope] attribute to make sure that it 401s
			// for anon users inside [AllowUsersAndServices]... otherwise it might 401
			// inside [RequiredScope(...)] depending on the order inside
			// DefaultAuthorizationAttribute.
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
