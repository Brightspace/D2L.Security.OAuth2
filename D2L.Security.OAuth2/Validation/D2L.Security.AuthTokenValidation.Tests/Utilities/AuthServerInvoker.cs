using System.IO;
using System.Net;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Web;

namespace D2L.Security.AuthTokenValidation.Tests.Utilities {

	internal static class AuthServerInvoker {
		
		public static string AuthenticateAndGetJWT( string clientId, string clientSecret, string scope ) {
			HttpWebRequest request = (HttpWebRequest)HttpWebRequest.Create( TestUris.AUTH_TOKEN_PROVISIONING_URI );
			request.Method = "POST";
			request.ContentType = "application/x-www-form-urlencoded";

			string authorizationHeaderValue = HttpUtility.UrlEncode( clientId ) + ":" + HttpUtility.UrlEncode( clientSecret );
			authorizationHeaderValue = authorizationHeaderValue.ToBase64();
			authorizationHeaderValue = "Basic " + authorizationHeaderValue;
			request.Headers["Authorization"] = authorizationHeaderValue;

			string formContents = "grant_type=client_credentials&scope=" + scope;
			using( StreamWriter write = new StreamWriter( request.GetRequestStream() ) ) {
				write.Write( formContents );
			}

			WebResponse response = request.GetResponse();

			DataContractJsonSerializer serializer = new DataContractJsonSerializer( typeof( AuthServerResponse ) );
			AuthServerResponse authServerResponse = (AuthServerResponse)serializer.ReadObject( response.GetResponseStream() );

			return authServerResponse.access_token;
		}

		[DataContract]
		internal sealed class AuthServerResponse {
			[DataMember]
			public string access_token { get; set; }
			[DataMember]
			public string token_type { get; set; }
			[DataMember]
			public string expires_in { get; set; }
		}
	}
}
