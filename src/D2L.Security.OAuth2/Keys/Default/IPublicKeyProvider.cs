using System.Threading.Tasks;
using D2L.CodeStyle.Annotations;

namespace D2L.Security.OAuth2.Keys.Default {

	/// <summary>
	/// An abstraction for fetching public keys
	/// </summary>
	internal partial interface IPublicKeyProvider {

		/// <summary>
		/// Gets an individual <see cref="D2LSecurityToken"/> by its <paramref name="id"/>
		/// </summary>
		/// <param name="id">The key id (kid)</param>
		/// <returns>The <see cref="D2LSecurityToken"/> or null if the key doesn't exist or has expired</returns>
		[GenerateSync]
		Task<D2LSecurityToken> GetByIdAsync( string id );

		/// <summary>
		/// Perform steps to potentially make future key fetches faster.
		/// </summary>
		[GenerateSync]
		Task PrefetchAsync();

	}
}
