using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using D2L.Security.BrowserAuthTokens.Default.Serialization;

namespace D2L.Security.BrowserAuthTokens.Default {
	internal static class AuthServerInvoker {

		/*
		CLAIMS IN FORM:
		
		grant_type    urn:ietf:params:oauth:grant-type:jwt-bearer
		assertion    (signed assertion grant JWT)
		scope     just like for client
		*/

		internal static async Task<string> AuthenticateAndGetJwt( Uri tokenProvisioningUrl, string jwt, string scope ) {
			HttpWebRequest request = (HttpWebRequest)HttpWebRequest.Create( tokenProvisioningUrl );
			request.Method = "POST";
			request.ContentType = "application/x-www-form-urlencoded";

			//string authorizationHeaderValue = HttpUtility.UrlEncode( clientId ) + ":" + HttpUtility.UrlEncode( clientSecret );

			//string authorizationHeaderValue = "bogus";
			//authorizationHeaderValue = authorizationHeaderValue.ToBase64();
			//authorizationHeaderValue = "Basic " + authorizationHeaderValue;
			//request.Headers["Authorization"] = authorizationHeaderValue;

			string formContents = "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer";
			formContents += "&scope=" + scope;
			formContents += "&assertion=" + jwt;

			using( StreamWriter write = new StreamWriter( request.GetRequestStream() ) ) {
				write.Write( formContents );
			}

			using( WebResponse response = await request.GetResponseAsync() ) {
				return response.ContentLength.ToString();
			}
		}
		
		internal static string MakeJwt2( X509Certificate2 certificate ) {
			string userId = "dummyuserid";
			string tenantId = "dummytenantid";
			string tenantUrl = "dummytenanturl";
			string xsrf = "dummyxsrf";

			DateTime expiry = DateTime.UtcNow + TimeSpan.FromMinutes( 30 );
			//long expirySeconds = expiry.GetSecondsSinceUnixEpoch();
			
			IList<Claim> claims = new List<Claim>();
			claims.Add( new Claim( "sub", userId ) );
			claims.Add( new Claim( "tenantid", tenantId ) );
			claims.Add( new Claim( "tenanturl", tenantUrl ) );
			claims.Add( new Claim( "xt", xsrf ) );

			SigningCredentials credentials = new X509SigningCredentials( certificate );

			JwtSecurityToken jwt = new JwtSecurityToken(
                "lms.dev.d2l",
                "https://api.brightspace.com/auth/token",
                claims,
                null,
                expiry,
                credentials
				);

			//var x509credential = credentials as X509SigningCredentials;
			//if (x509credential != null)
			//{
			//	jwt.Header.Add("kid", Base64Url(x509credential.Certificate.GetCertHash()));
			//}

			JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            return handler.WriteToken(jwt);
		}

		//private static string MakeJwt() {
		//	string header = MakeHeader();
		//	string payload = MakePayload();

		//	string base64UrlHeader = Base64Url( header );
		//	string base64UrlPayload = Base64Url( payload );
		//	//string signature = "DUMMYSIGNATURE";
		//	//signature = rsaService.SignData( Encoding.UTF8.GetBytes( base64UrlHeader + "." + base64UrlPayload ), oid );

		//	byte[] signature;
		//	using( RSACryptoServiceProvider rsaService = new RSACryptoServiceProvider() ) {
		//		rsaService.PersistKeyInCsp = false;
		//		rsaService.ImportParameters( rsaParams );
		//		byte[] payloadBytes = Encoding.UTF8.GetBytes( payload );
		//		string oid = CryptoConfig.MapNameToOID( "SHA256" );
		//		signature = rsaService.SignData( Encoding.UTF8.GetBytes( base64UrlHeader + "." + base64UrlPayload ), oid );
		//	}

		//}

		private static string Sign( string dataToSign ) {
			
			byte[] certificateRawData = new byte[1337];
			X509Certificate2 certificate = new X509Certificate2( certificateRawData );

			//X509Certificate2Collection certificate2Collection = new X509Certificate2Collection( certificate );
			//certificate2Collection.Import(certificateFilePath, "**password**", X509KeyStorageFlags.DefaultKeySet);
			

			//Only one cert in pks file
			//var cert2 = certificate2Collection[0];

			//create data to be signed
			//var time = DateTime.Now.ToString("dd/MM/yyyy") + " 00:00:00";
			//var modifiedTimestamp = userName + "|" + time;
			//var dataToSign = Encoding.ASCII.GetBytes(modifiedTimestamp);

			ContentInfo content = new ContentInfo( Encoding.ASCII.GetBytes( dataToSign ) );
			SignedCms signedMessage = new SignedCms(content);

			CmsSigner cmsSigner = new CmsSigner( certificate );
			signedMessage.ComputeSignature( cmsSigner );

			byte[] signedBytes = signedMessage.Encode();
			string result = Convert.ToBase64String( signedBytes );

			return result;
		}

		internal static RSAParameters CreateRSAParams() {
			using( RSACryptoServiceProvider rsaService = new RSACryptoServiceProvider( 2048 ) ) {
				rsaService.PersistKeyInCsp = false;
				RSAParameters rsaParams = rsaService.ExportParameters( true );
				return rsaParams;
			}
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

		private static string Base64Url( string s ) {
			return Base64Url( Encoding.UTF8.GetBytes( s ) );
		}

		private static string Base64Url( byte[] s ) {
			return Convert.ToBase64String( s )
				.Replace( '+', '-' )
				.Replace( '/', '_' )
				.Trim( '=' );
		}
	}
}
