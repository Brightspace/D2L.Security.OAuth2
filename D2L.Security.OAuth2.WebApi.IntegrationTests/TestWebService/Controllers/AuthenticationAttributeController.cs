using System.Web.Http;
using D2L.Security.OAuth2.Authorization;

namespace D2L.Security.OAuth2.TestWebService.Controllers {
	[DefaultAuthorization]
	[Authentication( PrincipalType.User )]
	public sealed class AuthenticationAttributeController : ApiController {
		[HttpGet]
		[RequireScope("a","b","c")]
		[Route("allowfrom/default")]
		public void Default() {
			
		}

		[HttpGet]
		[RequireScope("a","b","c")]
		[Route("allowfrom/servicesonly")]
		[Authentication( PrincipalType.Service )]
		public void ServicesOnly() {
			
		}

		[HttpGet]
		[RequireScope("a","b","c")]
		[Route("allowfrom/usersorservices")]
		[Authentication( PrincipalType.User | PrincipalType.Service )]
		public void UsersOrServices() {
			
		}

		[HttpGet]
		[NoRequiredScope]
		[Route("allowfrom/anonymous")]
		[Authentication( PrincipalType.Anonymous )]
		public void Anonymous() {
			
		}
	}
}
