using System;

namespace D2L.Security.AuthTokenValidation.PublicKeys {
	
	interface IPublicKeyProvider : IDisposable {
		IPublicKey Create();
	}
}
