using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using static D2L.CodeStyle.Annotations.Objects;

namespace D2L.Security.OAuth2.Keys {

	/// <summary>
	/// Data provider for public keys that belong to this service
	/// </summary>
	[Immutable]
	public interface IPublicKeyDataProvider {

		/// <summary>
		/// Gets an individual <see cref="JsonWebKey"/> by its <paramref name="id"/>
		/// </summary>
		/// <param name="id">The key id (kid)</param>
		/// <returns>The <see cref="JsonWebKey"/> or null if the key doesn't exist or has expired</returns>
		Task<JsonWebKey> GetByIdAsync( Guid id );

		/// <summary>
		/// Gets all the <see cref="JsonWebKey"/> instances
		/// </summary>
		/// <returns>All keys which haven't expired</returns>
		Task<IEnumerable<JsonWebKey>> GetAllAsync();

		/// <summary>
		/// Saves a key
		/// </summary>
		/// <param name="key">The key to save</param>
		Task SaveAsync( JsonWebKey key );

		/// <summary>
		/// Deletes a key by key <paramref name="id"/> (kid)
		/// </summary>
		/// <param name="id">The key id (kid) of the key to delete</param>
		Task DeleteAsync( Guid id );

	}
}