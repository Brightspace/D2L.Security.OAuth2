using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Keys.Local.Default {
	internal sealed class KeyManager : IKeyManager {
		private readonly IPublicKeyProvider m_publicKeyProvider;
		private readonly IPrivateKeyProvider m_privateKeyProvider;

		public KeyManager(
			IPublicKeyProvider publicKeyProvider,
			IPrivateKeyProvider privateKeyProvider
		) {
			m_publicKeyProvider = publicKeyProvider;
			m_privateKeyProvider = privateKeyProvider;
		}

		Task<JsonWebKey> IPublicKeyProvider.GetByIdAsync( Guid id ) {
			return m_publicKeyProvider.GetByIdAsync( id );
		}

		Task<IEnumerable<JsonWebKey>> IPublicKeyProvider.GetAllAsync() {
			return m_publicKeyProvider.GetAllAsync();
		}

		IJsonWebTokenSigner IKeyManager.CreateJsonWebTokenSigner( string issuer ) {
			var jsonWebTokenSigner = new JsonWebTokenSigner( m_privateKeyProvider, issuer );
			return jsonWebTokenSigner;
		}
	}
}
