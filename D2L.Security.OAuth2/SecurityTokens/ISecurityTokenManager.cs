using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.SecurityTokens {
	public interface ISecurityTokenManager {
		/// <summary>
		/// Get the latest security token (determined by the ValidTo property.)
		/// </summary>
		/// <remarks>
		/// They SecurityToken inside this token will have private key material.
		/// </remarks>
		Task<D2LSecurityToken> GetLatestTokenAsync();

		/// <summary>
		/// Get all security tokens.
		/// </summary>
		/// <remarks>
		/// Whether the D2LSecurityTokens returned by this function have private
		/// key material is implementation-defined.
		/// </remarks>
		Task<IEnumerable<D2LSecurityToken>> GetAllTokens();

		Task DeleteAsync( Guid id );

		Task SaveAsync( D2LSecurityToken token );
	}
}