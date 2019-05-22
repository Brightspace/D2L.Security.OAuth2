using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Utilities;
using D2L.Services;

namespace D2L.Security.OAuth2.Keys.Default {
	internal sealed class ExpiringPublicKeyDataProvider : ISanePublicKeyDataProvider {
		private readonly IPublicKeyDataProvider m_inner;
		private readonly IDateTimeProvider m_dateTimeProvider;

		public ExpiringPublicKeyDataProvider(
			IPublicKeyDataProvider inner,
			IDateTimeProvider dateTimeProvider
		) {
			if( inner == null ) {
				throw new ArgumentNullException( "inner" );
			}

			if( dateTimeProvider == null ) {
				throw new ArgumentException( nameof( dateTimeProvider ) );
			}

			m_inner = inner;
			m_dateTimeProvider = dateTimeProvider;
		}

		async Task<JsonWebKey> IPublicKeyDataProvider.GetByIdAsync( Guid id ) {
			// We are intentionally fetching *all* public keys from the database
			// here. This allows us to clean up all expired public keys even if
			// GetAllAsync() is never explicitly called (e.g. when we switch from
			// fetching jwks to specific-JWK in the validation code.)
			//
			// This is to avoid database bloat, not about maintaining functionality
			//
			// It would be more appealing for this to be a background task but
			// since this is a library that is challenging. Since there shouldn't
			// be too many public keys anyway and people should cache the JWKs
			// we should be fine.
			IEnumerable<JsonWebKey> keys = await ( this as IPublicKeyDataProvider )
				.GetAllAsync()
				.SafeAsync();

			// Using ToList() is important to force evaluation for each key
			// (SingleOrDefault bails early.) This is actually redundant due to
			// how GetAllAsync is implemented at the moment, but still.
			keys = keys.ToList();

			JsonWebKey key = keys.SingleOrDefault( jwk => new Guid( jwk.Id ) == id );

			return key;
		}

		async Task<IEnumerable<JsonWebKey>> IPublicKeyDataProvider.GetAllAsync() {
			IEnumerable<JsonWebKey> keys = await m_inner
				.GetAllAsync()
				.SafeAsync();

			keys = await Task
				.WhenAll(
					keys.Select( key => KeyExpirationHelper( key ) ).ToArray()
				)
				.SafeAsync();

			keys = keys
				.Where( key => key != null )
				.ToArray();

			return keys;
		}

		Task IPublicKeyDataProvider.SaveAsync( JsonWebKey key ) {
			return m_inner.SaveAsync( key );
		}

		Task IPublicKeyDataProvider.DeleteAsync( Guid id ) {
			return m_inner.DeleteAsync( id );
		}

		private async Task<JsonWebKey> KeyExpirationHelper( JsonWebKey key ) {
			if( key == null ) {
				return null;
			}

			if( key.ExpiresAt == null ) {
				throw new InvalidOperationException( "Stored public keys need expiry info" );
			}

			TimeSpan dt = key.ExpiresAt.Value - m_dateTimeProvider.UtcNow;

			if( dt < TimeSpan.FromSeconds( 0 ) ) {
				await ( this as IPublicKeyDataProvider )
					.DeleteAsync( new Guid( key.Id ) )
					.SafeAsync();
				return null;
			}

			return key;
		}
	}
}
