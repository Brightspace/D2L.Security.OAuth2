using System;
using System.Text;

namespace D2L.Security.AuthTokenValidation.Tests {
	internal static class StringExtensions {

		internal static string ToBase64( this string me ) {
			byte[] plainTextBytes = Encoding.UTF8.GetBytes( me );
			return Convert.ToBase64String( plainTextBytes );
		}
	}
}
