using System.Web.Http;
using D2L.Security.OAuth2.Authorization;
using D2L.Security.OAuth2.Principal;

namespace D2L.Security.OAuth2.TestWebService.Controllers {
	[DefaultAuthorization]
	public sealed class AuthorizationAttributeTestsController : ApiController {
		[HttpGet]
		[Authentication( PrincipalType.Service )]
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
		[Authentication( PrincipalType.User )]
		[Route("authorization/basic")]
		public void Basic() {
			
		}

		[HttpGet]
		[NoRequiredScope]
		[Authentication( PrincipalType.User | PrincipalType.Service )]
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
