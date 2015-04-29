using System;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Keys.Remote.Data {
	internal interface IJwksProvider {
		Task<JwksResponse> RequestJwksAsync( Uri authEndpoint, bool skipCache = false );
	}
}
