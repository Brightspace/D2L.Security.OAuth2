using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Keys.Default.Data {
	internal interface IJwksProvider {
		Task<JsonWebKeySet> RequestJwksAsync();
	}
}
