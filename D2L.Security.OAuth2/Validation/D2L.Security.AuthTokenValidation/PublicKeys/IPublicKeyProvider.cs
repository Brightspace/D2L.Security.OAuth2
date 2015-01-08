using System.Threading.Tasks;

namespace D2L.Security.AuthTokenValidation.PublicKeys {
	interface IPublicKeyProvider {
		Task<IPublicKey> Fetch();
	}
}
