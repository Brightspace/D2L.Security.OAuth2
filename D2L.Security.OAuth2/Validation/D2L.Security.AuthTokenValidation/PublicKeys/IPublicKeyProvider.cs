using System;

namespace D2L.Security.AuthTokenValidation.PublicKeys {
	
	interface IPublicKeyProvider {
		IPublicKey Create();
	}
}
