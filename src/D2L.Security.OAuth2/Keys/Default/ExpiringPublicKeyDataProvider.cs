using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using D2L.CodeStyle.Annotations;
using D2L.Security.OAuth2.Utilities;
using D2L.Services;

namespace D2L.Security.OAuth2.Keys.Default {
	internal sealed partial class ExpiringPublicKeyDataProvider : ISanePublicKeyDataProvider {
		private readonly IPublicKeyDataProvider m_inner;
		private readonly IDateTimeProvider m_dateTimeProvider;

		public ExpiringPublicKeyDataProvider(
			IPublicKeyDataProvider inner,
			IDateTimeProvider dateTimeProvider
		) {
			m_inner = inner ?? throw new ArgumentNullException( nameof( inner ) );
			m_dateTimeProvider = dateTimeProvider ?? throw new ArgumentException( nameof( dateTimeProvider ) );
		}

		[GenerateSync]
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
				.ConfigureAwait( false );

			// Using ToList() is important to force evaluation for each key
			// (SingleOrDefault bails early.) This is actually redundant due to
			// how GetAllAsync is implemented at the moment, but still.
			keys = keys.ToList();

			JsonWebKey key = keys.SingleOrDefault( jwk => new Guid( jwk.Id ) == id );

			return key;
		}

		[GenerateSync]
		async Task<IEnumerable<JsonWebKey>> IPublicKeyDataProvider.GetAllAsync() {
			IEnumerable<JsonWebKey> keys = await m_inner
				.GetAllAsync()
				.ConfigureAwait( false );

			var result = new List<JsonWebKey>();

			foreach( var key in keys ) {
				bool expired = await KeyExpiryHelperAsync( key ).ConfigureAwait( false );

				if( !expired ) {
					result.Add( key );
				}
			}

			return result;
		}

		[GenerateSync]
		Task IPublicKeyDataProvider.SaveAsync( Guid id, JsonWebKey key ) {
			return m_inner.SaveAsync( id, key );
		}

		[GenerateSync]
		Task IPublicKeyDataProvider.DeleteAsync( Guid id ) {
			return m_inner.DeleteAsync( id );
		}

		[GenerateSync]
		private async Task<bool> KeyExpiryHelperAsync( JsonWebKey key ) {
			if( key == null ) {
				return true;
			}

			if( key.ExpiresAt == null ) {
				throw new InvalidOperationException( "Stored public keys need expiry info" );
			}

			TimeSpan dt = key.ExpiresAt.Value - m_dateTimeProvider.UtcNow;

			if( dt < TimeSpan.FromSeconds( 0 ) ) {
				await ( this as IPublicKeyDataProvider )
					.DeleteAsync( new Guid( key.Id ) )
					.ConfigureAwait( false );

				return true;
			}

			return false;
		}
	}
}
