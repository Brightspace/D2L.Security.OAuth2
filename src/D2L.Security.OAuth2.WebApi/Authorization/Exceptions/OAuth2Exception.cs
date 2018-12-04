using System;
using System.Net;

namespace D2L.Security.OAuth2.Authorization.Exceptions {
	internal class OAuth2Exception : Exception {
		// Note: the naming style of these enum values matches the codes from RFC6750
		public enum Type {
			invalid_request = HttpStatusCode.BadRequest,
			invalid_token = HttpStatusCode.Unauthorized,
			insufficient_scope = HttpStatusCode.Forbidden
		}

		internal OAuth2Exception(
			Type error,
			string errorDescription,
			Exception innerException = null
		) : base(
			message: $"{ error }: { errorDescription }",
			innerException: innerException
		) {
			Error = error;
			ErrorDescription = errorDescription;

			if( errorDescription.Contains( "\"" ) ) {
				throw new ArgumentException( nameof( errorDescription ), "Must not contain '\"' character" );
			}
		}

		public Type Error { get; }
		public string ErrorDescription { get; }
	}
}