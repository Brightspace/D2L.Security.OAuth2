using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Keys.Development {

	/// <summary>
	/// A simple in-memory key data provider to be used only for testing and prototyping purposes.
	/// </summary>
	[Obsolete( "Only use this in tests and for prototyping without a db" )]
	public sealed class InMemoryPublicKeyDataProvider : IPublicKeyDataProvider {
		private readonly ConcurrentDictionary<string, JsonWebKey> m_keys = new ConcurrentDictionary<string, JsonWebKey>();

		Task<JsonWebKey> IPublicKeyDataProvider.GetByIdAsync( string id ) {
			if( !m_keys.TryGetValue( id, out JsonWebKey key ) ) {
				return Task.FromResult<JsonWebKey>( null );
			}
			return Task.FromResult( key );
		}

		Task<IEnumerable<JsonWebKey>> IPublicKeyDataProvider.GetAllAsync() {
			IEnumerable<JsonWebKey> result =
				new ReadOnlyCollection<JsonWebKey>( m_keys.Values.ToList() );

			return Task.FromResult( result );
		}

		Task IPublicKeyDataProvider.SaveAsync( JsonWebKey key ) {
			if( !m_keys.TryAdd( key.Id, key ) ) {
				throw new InvalidOperationException( "Attempted to add a key twice" );
			}
			return Task.Delay( 0 );
		}

		Task IPublicKeyDataProvider.DeleteAsync( string id ) {
			m_keys.TryRemove( id, out JsonWebKey removedKey );
			return Task.Delay( 0 );
		}
	}
}
