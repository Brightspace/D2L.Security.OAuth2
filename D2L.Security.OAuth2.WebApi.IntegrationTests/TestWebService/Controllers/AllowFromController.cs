using System.Web.Http;
using D2L.Security.OAuth2.Authorization;

namespace D2L.Security.OAuth2.TestWebService.Controllers {
	[DefaultAuthorization]
	[AllowFrom( users: true )]
	public sealed class AllowFromController : ApiController {
		[HttpGet]
		[RequireScope("a","b","c")]
		[Route("allowfrom/default")]
		public void Default() {
			
		}

		[HttpGet]
		[RequireScope("a","b","c")]
		[Route("allowfrom/servicesonly")]
		[AllowFrom( users: false, services: true )]
		public void ServicesOnly() {
			
		}
	}
}
