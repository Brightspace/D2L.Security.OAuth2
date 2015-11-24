using System.Web.Http;
using D2L.Security.OAuth2.Authorization;
using D2L.Security.OAuth2.Principal;

namespace D2L.Security.OAuth2.TestWebService.Controllers {
	[DefaultAuthorization]
	public sealed class AuthorizationAttributeTestsController : ApiController {
		[HttpGet]
		[AllowFrom( services: true )]
		[Route("authorization/unspecifiedscope")]
		public void UnspecifiedScope() {
			// Will crash because we forgot a [RequireScope(...)]	
		}

		[HttpGet]
		[RequireScope("foo", "bar", "baz")]
		[Route("authorization/unspecifiedprincipaltype")]
		public void UnspecifiedPrincipalType() {
			// Will crash because we forgot an [AllowFrom(...)]	
		}

		[HttpGet]
		[RequireScope("foo","bar","baz")]
		[AllowFrom( users: true )]
		[Route("authorization/basic")]
		public void Basic() {
			
		}

		[HttpGet]
		[NoRequiredScope]
		[AllowFrom( users: true, services: true )]
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
