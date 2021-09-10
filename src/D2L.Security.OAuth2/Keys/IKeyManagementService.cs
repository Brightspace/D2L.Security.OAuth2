using System;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Keys {
	public interface IKeyManagementService {
		/// <summary>
		/// Generates a new key (storing it's public and private keys) if the
		/// existing ones are getting near their expiry.
		///
		/// You would call this in a background job on a regular + frequent
		/// cadence.
		/// </summary>
		Task GenerateNewKeyIfNeededAsync();

		/// <summary>
		/// Causes the key manager to go looking for a new private key from the
		/// key store.
		/// </summary>
		/// <returns>
		/// The amount of time to wait before calling this again.
		/// </returns>
		Task<TimeSpan> RefreshKeyAsync();
	}
}
