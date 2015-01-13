using System.IO;
using System.Net;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Web;

namespace D2L.Security.AuthTokenValidation.Tests.Utilities {

	internal static class LOReSScopes {
		internal static readonly string MANAGE = "https://api.brightspace.com/auth/lores.manage";
	}

	internal static class LOReSManager {
		internal static readonly string CLIENT_ID = "lores_manager_client";
		internal static readonly string SECRET = "lores_manager_secret";
	}

	internal static class AuthServerInvoker {

		internal static readonly string AUTH_SERVER = "https://phwinsl01.proddev.d2l:44333/core/";
		private static readonly string AUTH_TOKEN_PROVISIONING_URL = "https://phwinsl01.proddev.d2l:44333/core/connect/token";
		
		public static string AuthenticateAndGetJWT( string clientId, string clientSecret, string scope ) {
			string authenticateHeaderValue = HttpUtility.UrlEncode( clientId ) + ":" + HttpUtility.UrlEncode( clientSecret );
			authenticateHeaderValue = authenticateHeaderValue.ToBase64();
			authenticateHeaderValue = "Basic " + authenticateHeaderValue;

			string formContents = "grant_type=client_credentials&scope=" + scope;

			HttpWebRequest request = (HttpWebRequest)HttpWebRequest.Create(AUTH_TOKEN_PROVISIONING_URL);
			request.Method = "POST";
			request.ContentType = "application/x-www-form-urlencoded";
			request.Headers["Authorization"] = authenticateHeaderValue;

			using( StreamWriter write = new StreamWriter( request.GetRequestStream() ) ) {
				write.Write( formContents );
			}

			HttpWebResponse response = request.GetResponse() as HttpWebResponse; // Exception here

			DataContractJsonSerializer serializer = new DataContractJsonSerializer( typeof( AuthServerResponse ) );
			AuthServerResponse authServerResponse = (AuthServerResponse)serializer.ReadObject( response.GetResponseStream() );

			return authServerResponse.access_token;
		}
	}

	[DataContract]
	public sealed class AuthServerResponse {
		[DataMember]
		public string access_token { get; set; }
		[DataMember]
		public string token_type { get; set; }
		[DataMember]
		public string expires_in { get; set; }
	}
}
