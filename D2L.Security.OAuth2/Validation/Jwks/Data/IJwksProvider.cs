using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Validation.Jwks.Data {
	internal interface IJwksProvider {
		Task<JwksResponse> RequestJwksAsync( Uri jwksEndpoint, bool skipCache = false );
	}
}
