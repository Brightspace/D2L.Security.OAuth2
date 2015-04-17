using System;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Keys.Remote.Data {
	internal interface IJwksProvider {
		Task<JwksResponse> RequestJwksAsync( Uri jwksEndpoint, bool skipCache = false );
	}
}
