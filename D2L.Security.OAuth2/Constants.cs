using System;

namespace D2L.Security.OAuth2 {
	/// <summary>
	/// OAuth2-related constants
	/// </summary>
	public static class Constants {
		/// <summary>
		/// The value for the "aud" claim for access tokens.
		/// </summary>
		public const string ACCESS_TOKEN_AUDIENCE = "https://api.brightspace.com/auth/token";

		/// <summary>
		/// The value for the "iss" claim for access tokens created by the auth
		/// service
		/// </summary>
		public const string ACCESS_TOKEN_ISSUER = "https://api.brightspace.com/auth";

		/// <summary>
		/// The value for the "aud" claim for JWT assertions created by clients
		/// during the JWT_BEARER grant flow.
		/// This probably should have been equal to ACCESS_TOKEN_ISSUER but we
		/// goofed.
		/// </summary>
		public const string ASSERTION_AUDIENCE = "https://api.brightspace.com/auth/token";

		/// <summary>
		/// The lifetime of assertion JWTs created during the JWT_BEARER grant
		/// flow
		/// </summary>
		internal static readonly TimeSpan ASSERTION_TOKEN_LIFETIME = TimeSpan.FromMinutes( 30 );

		/// <summary>
		/// D2L-standard claim names that may show up in JWTs
		/// </summary>
		public static class Claims {
			/// <summary>
			/// The "audience" for this JWT. Currently not really used. See the
			/// TENANT_ID claim for something that behaves like this implies.
			/// </summary>
			public const string AUDIENCE = "aud";

			/// <summary>
			/// The name of the integration that acquired this access token
			/// </summary>
			public const string CLIENT_ID = "client_id";

			/// <summary>
			/// The Unix timestamp for when this JWT expires
			/// </summary>
			public const string EXPIRY = "exp";

			/// <summary>
			/// Indicates who created + signed the JWT
			/// </summary>
			public const string ISSUER = "iss";

			/// <summary>
			/// The name of the key used to sign this JWT (always a GUID)
			/// </summary>
			public const string KEY_ID = "kid";

			/// <summary>
			/// A Unix timestamp for the earliest point at which this JWT
			/// should be considered valid.
			/// </summary>
			public const string NOT_BEFORE = "nbf";

			/// <summary>
			/// The OAuth2 scopes for an access token; used for authorization
			/// </summary>
			public const string SCOPE = "scope";

			/// <summary>
			/// Which tenant the JWT is scoped to (always a GUID)
			/// </summary>
			public const string TENANT_ID = "tenantid";

			/// <summary>
			/// A unique ID for the JWT (always a GUID)
			/// </summary>
			public const string TOKEN_ID = "jti";

			/// <summary>
			/// The LE-local userId that the access token represents. Value
			/// is a string (that parses as an integer/UserId)
			/// </summary>
			public const string USER_ID = "sub";

			/// <summary>
			/// The XSRF token for a user access token. Only used by LE.
			/// </summary>
			public const string XSRF_TOKEN = "xt";
		}

		/// <summary>
		/// OAuth2 grant types
		/// </summary>
		public static class GrantTypes {
			/// <summary>
			/// See: https://tools.ietf.org/html/draft-ietf-oauth-jwt-bearer-12
			/// </summary>
			public const string JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer";

			/// <summary>
			/// See: https://tools.ietf.org/html/rfc6749#section-4.4
			/// </summary>
			public const string CLIENT_CREDENTIALS = "client_credentials";
		}

		/// <summary>
		/// This is a stupid hack. This is the value every LMS puts for its "iss"
		/// claim in assertions. The LMS is actually identified by the "tenantid"
		/// claim it sends. This exists for legacy reasons, maybe some day we can
		/// "fix" it.
		/// </summary>
		public const string LMS_CLIENT_ID = "lms.dev.d2l";
	}
}
