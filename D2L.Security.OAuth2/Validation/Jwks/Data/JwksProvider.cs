using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace D2L.Security.OAuth2.Validation.Jwks.Data {
	internal sealed class JwksProvider : IJwksProvider {

		async Task<string> IJwksProvider.RequestJwksAsync( Uri endpoint ) {

			// TODO: control httpclient creation?
			using( var httpClient = new HttpClient() ) {

				string jsonResponse;
				using( HttpResponseMessage response = await httpClient.GetAsync( endpoint ) ) {
					response.EnsureSuccessStatusCode();
					jsonResponse = await response.Content.ReadAsStringAsync();
				}

				return jsonResponse;
			}
		}
	}
}
