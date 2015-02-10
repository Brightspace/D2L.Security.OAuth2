using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;

namespace D2L.Security.BrowserAuthTokens.Default {
	internal static class SerializationHelper {

		internal static IAccessToken ExtractAccessToken( string serializedAssertionGrantResponse ) {
			DataContractJsonSerializer serializer = new DataContractJsonSerializer( typeof( AssertionGrantResponse ) );

			byte[] rawData = Encoding.UTF8.GetBytes( serializedAssertionGrantResponse );

			using( MemoryStream stream = new MemoryStream( rawData ) ) {
				AssertionGrantResponse response = (AssertionGrantResponse)serializer.ReadObject( stream );
				IAccessToken token = new AccessToken( response.access_token, response.expires_in );

				return token;
			}
		}

		[DataContract]
		private sealed class AssertionGrantResponse {
			[DataMember]
			public string access_token { get; set; }

			[DataMember]
			public long expires_in { get; set; }
		}
	}
}
