using System;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Keys.Default {

	/// <summary>
	/// An abstraction for fetching public keys
	/// </summary>
	internal interface IPublicKeyProvider {

		/// <summary>
		/// Gets an individual <see cref="D2LSecurityKey"/> by its <paramref name="id"/>
		/// </summary>
		/// <param name="id">The key id (kid)</param>
		/// <returns>The <see cref="D2LSecurityKey"/> or null if the key doesn't exist or has expired</returns>
		Task<D2LSecurityKey> GetByIdAsync( Guid id );

	}
}
