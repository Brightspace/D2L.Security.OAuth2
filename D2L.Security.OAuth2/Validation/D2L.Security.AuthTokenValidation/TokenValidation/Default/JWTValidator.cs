using System;
using D2L.Security.AuthTokenValidation.PublicKeys;

namespace D2L.Security.AuthTokenValidation.TokenValidation.Default {
	internal sealed class JWTValidator : IJWTValidator {

		private readonly IPublicKeyProvider m_keyProvider;

		internal JWTValidator( IPublicKeyProvider keyProvider ) {
			m_keyProvider = keyProvider;
		}

		bool IJWTValidator.TryValidate( string jwt, out IClaimsPrincipal claimsPrincipal ) {
			bool result = false;
			claimsPrincipal = null;

			try {
				result = TryValidateWorker( jwt, out claimsPrincipal );
			} catch {

			}

			return result;
		}

		private bool TryValidateWorker( string jwt, out IClaimsPrincipal claimsPrincipal ) {
			throw new NotImplementedException();
		}
	}
}
