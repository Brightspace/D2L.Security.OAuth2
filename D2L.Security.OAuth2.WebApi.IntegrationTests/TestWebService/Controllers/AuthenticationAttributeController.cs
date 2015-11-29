using System.Web.Http;
using D2L.Security.OAuth2.Authorization;

namespace D2L.Security.OAuth2.TestWebService.Controllers {
	[DefaultAuthorization]
	[Authentication( users: true )]
	public sealed class AuthenticationAttributeController : ApiController {
		[HttpGet]
		[RequireScope("a","b","c")]
		[Route("allowfrom/default")]
		public void Default() {
			
		}

		[HttpGet]
		[RequireScope("a","b","c")]
		[Route("allowfrom/servicesonly")]
		[Authentication( services: true )]
		public void ServicesOnly() {
			
		}

		[HttpGet]
		[RequireScope("a","b","c")]
		[Route("allowfrom/usersorservices")]
		[Authentication( users: true, services: true )]
		public void UsersOrServices() {
			
		}
	}
}
