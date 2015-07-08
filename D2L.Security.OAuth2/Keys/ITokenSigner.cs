using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Keys {

	/// <summary>
	/// An abstraction for signing tokens
	/// </summary>
	public interface ITokenSigner {

		/// <summary>
		/// Signs a token
		/// </summary>
		/// <param name="token">The token to be signed</param>
		/// <returns>The raw signed token as a <see cref="string"/></returns>
		Task<string> SignAsync( UnsignedToken token );
	}
}
