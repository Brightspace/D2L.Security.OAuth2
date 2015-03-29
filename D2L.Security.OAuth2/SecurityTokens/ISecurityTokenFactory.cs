using System;

namespace D2L.Security.OAuth2.SecurityTokens {
	public interface ISecurityTokenFactory {
		/// <summary>
		/// Creates a new D2LSecurityToken
		/// </summary>
		/// <param name="lifespan">
		/// The length of time the token will be valid for
		/// </param>
		/// <returns>
		/// A token ValidFrom now with a fresh KeyId
		/// </returns>
		D2LSecurityToken Create( TimeSpan lifespan );
	}
}
