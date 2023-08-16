using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using D2L.CodeStyle.Annotations;

namespace D2L.Security.OAuth2.Keys {
	/// <summary>
	/// An externally-implemented storage for private keys.
	/// </summary>
	public partial interface IPrivateKeyDataProvider {
		/// <summary>
		/// Save a private key.
		/// </summary>
		Task SaveAsync( PrivateKeyData keyData );

		/// <summary>
		/// Gets all non-expiring private keys.
		/// </summary>
		/// <param name="validUntilAtLeast">The earliest possible expiry time toreturn (should be in the future.)</param>
		/// <returns>All non-expired/expiring private keys</returns>
		[GenerateSync]
		Task<IEnumerable<PrivateKeyData>> GetAllAsync(
			DateTimeOffset validUntilAtLeast
		);
	}
}
