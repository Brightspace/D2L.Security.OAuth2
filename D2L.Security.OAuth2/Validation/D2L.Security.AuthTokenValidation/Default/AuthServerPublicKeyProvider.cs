using System;
using System.Security.Cryptography;

namespace D2L.Security.AuthTokenValidation.Default {

	internal sealed class AuthServerPublicKeyProvider : IAuthServerPublicKeyProvider {

		private readonly Uri m_authServiceEndpoint;

		public AuthServerPublicKeyProvider(
			Uri authServiceEndpoint
			) {
			m_authServiceEndpoint = authServiceEndpoint;
		}

		public CngKey Get() {
			throw new NotImplementedException();
		}
	}
}
