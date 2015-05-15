using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Keys.Local.Data {

	/// <summary>
	/// Data provider for public keys that belong to this service
	/// </summary>
	public interface IPublicKeyDataProvider {

		/// <summary>
		/// Gets a key by id
		/// </summary>
		/// <param name="id">The key id (kid)</param>
		/// <returns>The matching <see cref="JsonWebKey"/></returns>
		Task<JsonWebKey> GetByIdAsync( Guid id );

		/// <summary>
		/// Gets all the keys
		/// </summary>
		/// <returns>All the keys</returns>
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