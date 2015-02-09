using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace D2L.Security.BrowserAuthTokens.Invocation.Default {
	
	internal sealed class AuthServiceInvoker : IAuthServiceInvoker {

		private readonly Uri m_tokenProvisioningEndpoint;

		internal AuthServiceInvoker( Uri tokenProvisioningEndpoint ) {
			m_tokenProvisioningEndpoint = tokenProvisioningEndpoint;
		}

		async Task<string> IAuthServiceInvoker.ProvisionAccessToken( InvocationParameters invocationParams ) {
			HttpWebRequest request = (HttpWebRequest)HttpWebRequest.Create( m_tokenProvisioningEndpoint );
			request.Method = "POST";
			request.ContentType = "application/x-www-form-urlencoded";

			string clientId = "lms.dev.d2l";
			string clientSecret = "lms_secret";

			request.Headers["Authorization"] = invocationParams.Authorization;

			string formContents = "grant_type=" + invocationParams.GrantType;
			formContents += "&assertion=" + invocationParams.Assertion;

			formContents += "&scope=" + invocationParams.Scope;

			using( StreamWriter writer = new StreamWriter( request.GetRequestStream() ) ) {
				writer.Write( formContents );
			}

			using( WebResponse response = await request.GetResponseAsync() ) {
				using( Stream responseStream = response.GetResponseStream() ) {
					using( StreamReader reader = new StreamReader( responseStream ) ) {
						return reader.ReadToEnd();
					}
				}
			}
		}		
	}
}
