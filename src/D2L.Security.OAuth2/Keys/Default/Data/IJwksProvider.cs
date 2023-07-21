using System.Threading.Tasks;
using D2L.CodeStyle.Annotations;

namespace D2L.Security.OAuth2.Keys.Default.Data {
	internal partial interface IJwksProvider {
		[GenerateSync]
		Task<JsonWebKeySet> RequestJwksAsync();
		[GenerateSync]
		Task<JsonWebKeySet> RequestJwkAsync( string keyId );
		string Namespace { get; }
	}
}
