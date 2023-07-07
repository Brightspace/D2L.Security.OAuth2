﻿using D2L.CodeStyle.Annotations;
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
		private readonly ConcurrentDictionary<Guid, JsonWebKey> m_keys = new ConcurrentDictionary<Guid, JsonWebKey>();

		[GenerateSync]
		Task<JsonWebKey> IPublicKeyDataProvider.GetByIdAsync( Guid id ) {
			if( !m_keys.TryGetValue( id, out JsonWebKey key ) ) {
				return Task.FromResult<JsonWebKey>( null );
			}
			return Task.FromResult( key );
		}

		[GenerateSync]
		Task<IEnumerable<JsonWebKey>> IPublicKeyDataProvider.GetAllAsync() {
			IEnumerable<JsonWebKey> result =
				new ReadOnlyCollection<JsonWebKey>( m_keys.Values.ToList() );

			return Task.FromResult( result );
		}

		[GenerateSync]
		async Task IPublicKeyDataProvider.SaveAsync( Guid id, JsonWebKey key ) {
			if( !m_keys.TryAdd( id, key ) ) {
				throw new InvalidOperationException( "Attempted to add a key twice" );
			}
			await Task.CompletedTask.ConfigureAwait(false);
		}

		[GenerateSync]
		async Task IPublicKeyDataProvider.DeleteAsync( Guid id ) {
			m_keys.TryRemove( id, out JsonWebKey removedKey );
			await Task.CompletedTask.ConfigureAwait(false);
		}
	}
}
