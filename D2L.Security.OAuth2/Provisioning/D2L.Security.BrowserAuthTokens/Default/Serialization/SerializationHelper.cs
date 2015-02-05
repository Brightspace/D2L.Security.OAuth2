using System.IO;
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
	}
}
