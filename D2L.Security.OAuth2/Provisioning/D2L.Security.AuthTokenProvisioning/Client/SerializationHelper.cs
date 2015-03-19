using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;

namespace D2L.Security.AuthTokenProvisioning.Client {
	internal static class SerializationHelper {

		internal static IAccessToken ExtractAccessToken( Stream assertionGrantResponseStream ) {
			DataContractJsonSerializer serializer = new DataContractJsonSerializer( typeof( AssertionGrantResponse ) );

			AssertionGrantResponse response = (AssertionGrantResponse)serializer.ReadObject( assertionGrantResponseStream );
			IAccessToken token = new AccessToken( response.access_token, response.expires_in );

			return token;
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
