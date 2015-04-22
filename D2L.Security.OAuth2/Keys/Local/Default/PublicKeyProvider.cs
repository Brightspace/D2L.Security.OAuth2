using System;
using System.Collections.Generic;
using System.Threading.Tasks;

using D2L.Security.OAuth2.Keys.Local.Data;
using D2L.Security.OAuth2.Utilities;

namespace D2L.Security.OAuth2.Keys.Local.Default {
	internal class PublicKeyProvider : IPublicKeyProvider {
		private readonly IPublicKeyDataProvider m_publicKeyDataProvider;
		private readonly TimeSpan m_keyLifetime;

		public PublicKeyProvider(
			IPublicKeyDataProvider publicKeyDataProvider,
			TimeSpan keyLifetime
		) {
			m_publicKeyDataProvider = publicKeyDataProvider;
			m_keyLifetime = keyLifetime;
		}

		async Task<JsonWebKey> IPublicKeyProvider.GetByIdAsync( Guid id ) {
			JsonWebKey key = await m_publicKeyDataProvider.GetByIdAsync( id ).SafeAsync();
			key = await KeyExpirationHelper( key ).SafeAsync();
			return key;
		}

		async Task<IEnumerable<JsonWebKey>> IPublicKeyProvider.GetAllAsync() {
			IEnumerable<JsonWebKey> keys = await m_publicKeyDataProvider.GetAllAsync().SafeAsync();

			var result = new List<JsonWebKey>();
			foreach( JsonWebKey key in keys ) {
				var nonExpiredKey = await KeyExpirationHelper( key ).SafeAsync();
				if( nonExpiredKey != null ) {
					result.Add( nonExpiredKey );
				}
			}
			return result;
		}

		async Task<JsonWebKey> KeyExpirationHelper( JsonWebKey key ) {
			if( key == null ) {
				return null;
			}

			if( key.ExpiresAt == null ) {
				throw new InvalidOperationException( "Stored public keys need expiry info" );
			}

			TimeSpan dt = key.ExpiresAt.Value - DateTime.UtcNow;

			// If the key is expired, delete it
			if( dt < TimeSpan.FromSeconds( 0 ) ) {
				await m_publicKeyDataProvider.DeleteAsync( key.Id ).SafeAsync();
				return null;
			}

			// If the key lasts longer than expected, raise an alarm, but keep going
			if( dt > m_keyLifetime + m_keyLifetime ) {
				// TODO: but don't spam the logs for the same key because maybe we are changing things blue-green
			}

			return key;
		}
	}
}