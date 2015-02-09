using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace D2L.Security.BrowserAuthTokens.Default {
	internal static class SerializationHelper {

		internal static string SerializeScopes( IEnumerable<string> scopes ) {
			const string separator = " ";
			
			if( !scopes.Any() ) {
				return string.Empty;
			}

			StringBuilder builder = new StringBuilder();
			foreach( string scope in scopes ) {
				builder.Append( scope );
				builder.Append( separator );
			}

			string result = builder.ToString();
			// remove last separator
			result = result.Substring( 0, result.Length - separator.Length );

			return result;
		}
	}
}
