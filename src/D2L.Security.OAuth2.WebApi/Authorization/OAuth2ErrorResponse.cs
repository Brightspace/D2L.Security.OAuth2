using Newtonsoft.Json;

namespace D2L.Security.OAuth2.Authorization {
	internal sealed class OAuth2ErrorResponse {

		public OAuth2ErrorResponse(
			string error,
			string errorDescription
		) {
			Error = error;
			ErrorDescription = errorDescription;
		}

		[JsonProperty( "error", Required = Required.Always )]
		public string Error { get; }

		[JsonProperty( "error_description", Required = Required.Always )]
		public string ErrorDescription { get; }

		[JsonProperty( "scope" )]
		public string Scope { get; set; }

	}
}
