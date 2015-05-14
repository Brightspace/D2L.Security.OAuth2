using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Keys.Local {

	/// <summary>
	/// An abstraction for fetching public keys
	/// </summary>
	public interface IPublicKeyProvider {

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
	}
}
