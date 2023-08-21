using System.Threading.Tasks;
using D2L.CodeStyle.Annotations;

namespace D2L.Security.OAuth2.Keys {
	/// <summary>
	/// An abstraction for signing tokens
	/// </summary>
	public partial interface ITokenSigner {

		/// <summary>
		/// Signs a token
		/// </summary>
		/// <param name="token">The token to be signed</param>
		/// <returns>The raw signed token as a <see cref="string"/></returns>
		[GenerateSync]
		Task<string> SignAsync( UnsignedToken token );
	}
}
