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
			/// TENANT_ID claim for something that behaves like this implies
			/// https://tools.ietf.org/html/rfc7519#section-4.1.3
			/// </summary>
			public const string AUDIENCE = "aud";

			/// <summary>
			/// The body of a validated Caliper federated session id (providing
			/// LTI launch context info)
			/// (This is a D2L-custom claim)
			/// </summary>
			public const string CALIPER_FSID_BODY = "fsid";

			/// <summary>
			/// The name of the integration that acquired this access token
			/// </summary>
			public const string CLIENT_ID = "client_id";

			/// <summary>
			/// The Unix timestamp for when this JWT expires
			/// https://tools.ietf.org/html/rfc7519#section-4.1.4
			/// </summary>
			public const string EXPIRY = "exp";

			/// <summary>
			/// If this exists it indicates the "sub" of this token is being
			/// impersonated by the user indicated in this claim
			/// (This is a D2L-custom claim)
			/// </summary>
			public const string IMPERSONATING_USER_ID = "impsub";

			/// <summary>
			/// The Unix timestamp for when this JWT was issued
			/// https://tools.ietf.org/html/rfc7519#section-4.1.6
			/// </summary>
			public const string ISSUED_AT = "iat";

			/// <summary>
			/// Indicates who created + signed the JWT
			/// https://tools.ietf.org/html/rfc7519#section-4.1.1
			/// </summary>
			public const string ISSUER = "iss";

			/// <summary>
			/// The name of the key used to sign this JWT (always a GUID)
			/// https://tools.ietf.org/html/draft-ietf-jose-json-web-key-41#section-4.5
			/// </summary>
			public const string KEY_ID = "kid";

			/// <summary>
			/// A Unix timestamp for the earliest point at which this JWT
			/// should be considered valid
			/// https://tools.ietf.org/html/rfc7519#section-4.1.5
			/// </summary>
			public const string NOT_BEFORE = "nbf";

			/// <summary>
			/// The OAuth2 scopes for an access token; used for authorization
			/// https://tools.ietf.org/html/draft-ietf-oauth-jwt-bearer-12#section-2.1
			/// </summary>
			public const string SCOPE = "scope";

			/// <summary>
			/// Which tenant the JWT is scoped to (always a GUID)
			/// (This is a D2L-custom claim)
			/// </summary>
			public const string TENANT_ID = "tenantid";

			/// <summary>
			/// A unique ID for the JWT (always a GUID)
			/// https://tools.ietf.org/html/rfc7519#section-4.1.7
			/// </summary>
			public const string TOKEN_ID = "jti";

			/// <summary>
			/// The LE-local userId that the access token represents. Value
			/// is a string (that parses as an integer/UserId)
			/// https://tools.ietf.org/html/rfc7519#section-4.1.2
			/// </summary>
			public const string USER_ID = "sub";
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
