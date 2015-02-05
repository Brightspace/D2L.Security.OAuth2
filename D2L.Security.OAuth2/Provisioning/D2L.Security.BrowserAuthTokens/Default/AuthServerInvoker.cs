using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Threading.Tasks;
using D2L.Security.BrowserAuthTokens.Default.Serialization;

namespace D2L.Security.BrowserAuthTokens.Default {
	internal static class AuthServerInvoker {

		internal static string AuthenticateAndGetJwt( string tokenProvisioningUrl, string clientId, string clientSecret, string scope ) {
			HttpWebRequest request = (HttpWebRequest)HttpWebRequest.Create( tokenProvisioningUrl );
			request.Method = "POST";
			request.ContentType = "application/x-www-form-urlencoded";

			//string authorizationHeaderValue = HttpUtility.UrlEncode( clientId ) + ":" + HttpUtility.UrlEncode( clientSecret );

			string authorizationHeaderValue = "bogus";
			authorizationHeaderValue = authorizationHeaderValue.ToBase64();
			authorizationHeaderValue = "Basic " + authorizationHeaderValue;
			request.Headers["Authorization"] = authorizationHeaderValue;

			string formContents = "grant_type=client_credentials&scope=" + scope;
			using( StreamWriter write = new StreamWriter( request.GetRequestStream() ) ) {
				write.Write( formContents );
			}

			WebResponse response = request.GetResponse();

			DataContractJsonSerializer serializer = new DataContractJsonSerializer( typeof( GrantJwtHeader ) );
			GrantJwtHeader authServerResponse = (GrantJwtHeader)serializer.ReadObject( response.GetResponseStream() );

			//return authServerResponse.access_token;
			throw new NotImplementedException();
		}

		private static string MakeHeader() {
			GrantJwtHeader header = new GrantJwtHeader();
			return SerializationHelper.Serialize<GrantJwtHeader>( header );
		}

		private static string MakePayload() {
			GrantJwtPayload payload = new GrantJwtPayload(
				"dummyuserid",
				"dummytenantid",
				"dummytenanturl"
				);

			return SerializationHelper.Serialize<GrantJwtPayload>( payload );
		}

		internal static void TEST() {
		}

		internal static string ToBase64( this string me ) {
			byte[] plainTextBytes = Encoding.UTF8.GetBytes( me );
			return Convert.ToBase64String( plainTextBytes );
		}
	}
}
