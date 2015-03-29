using System;

namespace D2L.Security.OAuth2.SecurityTokens {
	public interface ISecurityTokenFactory {
		/// <summary>
		/// Creates a security token with the default lifespan.
		/// </summary>
		D2LSecurityToken Create();

		/// <summary>
		/// Creates a token with an explicit lifespan.
		/// Prefer the default overload.
		/// </summary>
		D2LSecurityToken Create( TimeSpan lifespan );
	}
}
