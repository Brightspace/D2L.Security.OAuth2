using System;
using System.Security.Cryptography;

namespace D2L.Security.AuthTokenValidation.Default {

	internal sealed class AuthServerPublicKeyProvider : IAuthServerPublicKeyProvider {
		public CngKey Get() {
			throw new NotImplementedException();
		}
	}
}
