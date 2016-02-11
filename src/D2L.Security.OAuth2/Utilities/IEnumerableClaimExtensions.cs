using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace D2L {

	/// <summary>
	/// Extension methods for <see cref="IEnumerable{Claim}"/>
	/// </summary>
	public static class IEnumerableClaimExtensions {

		/// <summary>
		/// Determines if a claim matching <paramref name="name"/> exists
		/// </summary>
		/// <param name="this"></param>
		/// <param name="name">The name of the claim to search for</param>
		/// <returns>True if a matching claim exists, otherwise false</returns>
		public static bool HasClaim( this IEnumerable<Claim> @this, string name ) {
			return @this.Any(c => c.Type == name);
		}

		/// <summary>
		/// Gets the claim matching <paramref name="name"/> if it exists
		/// </summary>
		/// <param name="this"></param>
		/// <param name="name">The name of the claim to search for</param>
		/// <param name="value">The value of the claim</param>
		/// <returns>True if a matching claim exists, otherwise false</returns>
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
