using System;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.SecurityTokens {
	public static class ISecurityTokenManagerExtensions {
		public static void DeleteFireAndForget( this ISecurityTokenManager @this, Guid id ) {
			Task.Run( () => @this.DeleteAsync( id ) );
		}
	}
}
