using System;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;

namespace D2L.Security.OAuth2.Provisioning.Default {
	internal static class SerializationHelper {

		internal static bool TryExtractAccessToken( string json, out IAccessToken token ) {
			AssertionGrantResponse response;
			if( TryDeserialize( json, out response ) ) {
				token = new AccessToken( response.access_token );
				return true;
			} else {
				token = null;
				return false;
			}
		}
		
		internal static bool TryExtractErrorMessage( string json, out string message ) {
			ErrorResponse response;
			if( TryDeserialize( json, out response ) ) {
				message = string.Concat( response.error, ": ", response.error_description );
				return true;
			} else {
				message = null;
				return false;
			}
		}
		
		private static bool TryDeserialize<T>( string json, out T obj ) {
			try {
				Stream jsonStream = new MemoryStream( Encoding.UTF8.GetBytes( json ) );
				var deserializer = new DataContractJsonSerializer( typeof( T ) );
				obj = (T)deserializer.ReadObject( jsonStream );
				return true;
			} catch( Exception ) {
				obj = default( T );
				return false;
			}
		}

		[DataContract]
		private sealed class AssertionGrantResponse {
			[DataMember( IsRequired = true )]
			public string access_token { get; set; }
		}
		
		[DataContract]
		private sealed class ErrorResponse {
			[DataMember( IsRequired = true )]
			public string error { get; set; }
			
			[DataMember( IsRequired = true )]
			public string error_description { get; set; }
		}
	}
}
