using System;
using System.IO;
using System.Net;
using System.Threading.Tasks;

namespace D2L.Security.AuthTokenProvisioning.Invocation.Default {
	
	internal sealed class AuthServiceInvoker : IAuthServiceInvoker {

		private readonly Uri m_tokenProvisioningEndpoint;

		internal AuthServiceInvoker( Uri tokenProvisioningEndpoint ) {
			m_tokenProvisioningEndpoint = tokenProvisioningEndpoint;
		}

		async Task<string> IAuthServiceInvoker.ProvisionAccessTokenAsync( InvocationParameters invocationParams ) {
			HttpWebRequest request = BuildRequest( invocationParams );

			using( WebResponse response = await request.GetResponseAsync() ) {
				using( Stream responseStream = response.GetResponseStream() ) {
					using( StreamReader reader = new StreamReader( responseStream ) ) {
						return reader.ReadToEnd();
					}
				}
			}
		}

		string IAuthServiceInvoker.ProvisionAccessToken( InvocationParameters invocationParams ) {
			HttpWebRequest request = BuildRequest( invocationParams );

			using( WebResponse response = request.GetResponse() ) {
				using( Stream responseStream = response.GetResponseStream() ) {
					using( StreamReader reader = new StreamReader( responseStream ) ) {
						return reader.ReadToEnd();
					}
				}
			}
		}

		private HttpWebRequest BuildRequest( InvocationParameters invocationParams ) {
			HttpWebRequest request = (HttpWebRequest)HttpWebRequest.Create( m_tokenProvisioningEndpoint );
			request.Method = "POST";
			request.ContentType = "application/x-www-form-urlencoded";

			request.Headers["Authorization"] = invocationParams.Authorization;

			string formContents = BuildFormContents( invocationParams );

			using( StreamWriter writer = new StreamWriter( request.GetRequestStream() ) ) {
				writer.Write( formContents );
			}

			return request;
		}

		private static string BuildFormContents( InvocationParameters invocationParams ) {
			string formContents = "grant_type=" + invocationParams.GrantType;
			formContents += "&assertion=" + invocationParams.Assertion;
			formContents += "&scope=" + invocationParams.Scope;

			return formContents;
		}
	}
}
