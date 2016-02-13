using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web.Http;

namespace D2L.Security.OAuth2.WebApi.TestWebService.Controllers {
	public sealed class AuthenticationFilterTestsController : ApiController {
		[HttpGet]
		[Route("authentication/basic")]
		public void Basic() {
			
		}

		[HttpGet]
		[OverrideAuthentication]
		[Route("authentication/anonymous")]
		public void Anonymous() {
			
		}
	}
}
