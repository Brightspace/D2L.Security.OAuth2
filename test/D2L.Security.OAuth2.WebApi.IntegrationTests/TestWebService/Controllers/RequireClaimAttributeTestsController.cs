using System.Web.Http;
using D2L.Security.OAuth2.Authorization;

namespace D2L.Security.OAuth2.TestWebService.Controllers {
	[Authentication( users: true, services: true )]
	public sealed class RequireClaimAttributeTestsController : ApiController {
		internal const string ROUTE = "authorization/requireclaim/sub";

		// This is a bit cheesy - requiring the "sub" claim with RequireClaim rather
		// than using the Authentication attribute with services set to false. That
		// being said it's still a complete test of this attribute that happens to
		// be easy to set up.
		[HttpGet]
		[Route( ROUTE )]
		[RequireClaim( Constants.Claims.USER_ID )]
		[NoRequiredScope]
		public void RequireSubjectClaimExplicitly() { }
	}
}
