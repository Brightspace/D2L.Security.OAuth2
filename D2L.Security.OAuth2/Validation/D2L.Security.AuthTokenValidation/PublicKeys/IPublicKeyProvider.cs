using System;
using System.Threading.Tasks;

namespace D2L.Security.AuthTokenValidation.PublicKeys {
	
	interface IPublicKeyProvider : IDisposable {
		Task<IPublicKey> Fetch();
	}
}
