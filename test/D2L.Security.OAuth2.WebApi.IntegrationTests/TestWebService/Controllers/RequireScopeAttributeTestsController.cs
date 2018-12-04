using System.Web.Http;
using D2L.Security.OAuth2.Authorization;

namespace D2L.Security.OAuth2.TestWebService.Controllers {
	[Authentication( users: true, services: true )]
	public sealed class RequireScopeAttributeTestsController : ApiController {
		internal const string ROUTE = "authorization/requirescope";
		[HttpGet]
		[Route( ROUTE )]
		[RequireScope( "a", "b", "c" )]
		public void RequireScope() { }
	}
}
