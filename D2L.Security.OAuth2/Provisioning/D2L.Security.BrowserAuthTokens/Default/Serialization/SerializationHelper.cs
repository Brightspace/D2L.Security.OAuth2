using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Json;
using System.Text;

namespace D2L.Security.BrowserAuthTokens.Default.Serialization {
	internal static class SerializationHelper {
		internal static string Serialize<T>( T source ) {
			DataContractJsonSerializer serializer = new DataContractJsonSerializer( typeof( T ) );

			using( MemoryStream stream = new MemoryStream() ) {
				serializer.WriteObject( stream, source );
				string result = Encoding.UTF8.GetString( stream.ToArray() );

				return result;
			}
		}

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
