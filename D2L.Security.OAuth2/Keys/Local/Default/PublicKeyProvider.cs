using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using D2L.Security.OAuth2.Keys.Local.Data;

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
			// We are intentionally fetching *all* public keys from the database
			// here. This allows us to clean up all expired public keys even if
			// GetAllAsync() is never explicitly called (e.g. when we switch from
			// fetching jwks to specific-JWK in the validation code.)
			//
			// It would be more appealing for this to be a background task but
			// since this is a library that is challenging. Since there shouldn't
			// be too many public keys anyway and people should cache the JWKs
			// we should be fine.
			var @this = this as IPublicKeyProvider;
			IEnumerable<JsonWebKey> keys = ( await @this.GetAllAsync().SafeAsync() );

			// Using ToList() is important to force evaluation for each key
			// (SingleOrDefault bails early.) This is actually redundant due to
			// how GetAllAsync is implemented at the moment, but still.
			List<JsonWebKey> freshKeys = keys.ToList();

			JsonWebKey key = freshKeys.SingleOrDefault( k => k.Id == id );

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