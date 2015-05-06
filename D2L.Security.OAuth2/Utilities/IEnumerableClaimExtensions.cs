using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace D2L {
	public static class IEnumerableClaimExtensions {
		public static bool HasClaim( this IEnumerable<Claim> @this, string name ) {
			return @this.Any(c => c.Type == name);
		}

		public static bool TryGetClaim( this IEnumerable<Claim> @this, string name, out string value ) {
			Claim claim = @this.FirstOrDefault( c => c.Type == name );

			if( claim == null ) {
				value = null;
				return false;
			}

			value = claim.Value;
			return true;
		}
	}
}
