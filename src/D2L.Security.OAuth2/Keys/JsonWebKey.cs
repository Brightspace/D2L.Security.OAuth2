#nullable enable

using System;
using System.Collections.Generic;
using D2L.Security.OAuth2.Keys.Default;
using Newtonsoft.Json;

namespace D2L.Security.OAuth2.Keys {
	/// <summary>
	/// Json Web Key (JWK) base class
	/// </summary>
	public abstract class JsonWebKey {

		/// <summary>
		/// The name of the key id (kid) property in the JWT
		/// </summary>
		public const string KEY_ID = "kid";

		private readonly string m_id;
		private readonly DateTime? m_expiresAt;

		internal abstract D2LSecurityToken ToSecurityToken();

		/// <summary>
		/// Construct a new <see cref="JsonWebKey"/> instance
		/// </summary>
		/// <param name="id">The key id (kid)</param>
		/// <param name="expiresAt">When the key expires</param>
		protected JsonWebKey( string id, DateTime? expiresAt ) {
			m_id = id;
			m_expiresAt = expiresAt;
		}

		/// <summary>
		/// The key id (kid)
		/// </summary>
		public virtual string Id {
			get { return m_id; }
		}

		/// <summary>
		/// When the key expires
		/// </summary>
		public virtual DateTime? ExpiresAt {
			get { return m_expiresAt; }
		}

		/// <summary>
		/// Converts the <see cref="RsaJsonWebKey"/> into a JWK DTO
		/// </summary>
		/// <returns>A JWK DTO</returns>
		public abstract object ToJwkDto();


		/// <summary>
		/// Deserialize a JWK
		/// </summary>
		/// <param name="json">The json JWK</param>
		/// <returns>A <see cref="JsonWebKey"/></returns>
		public static JsonWebKey FromJson( string json ) {
			if( !TryParseJsonSigningKey( json, out var result, out var error, out var e, out _ ) ) {
				throw new JsonWebKeyParseException( error, e );
			}

			return result;
		}

		public static bool TryParseJsonSigningKey(
			string json,
			[NotNullWhen( true )]
			out JsonWebKey? key,
			[NotNullWhen( false )]
			out string? error,
			[NullWhen( true )]
			out Exception? exception,
			out bool useEncKey
		) {
			Dictionary<string, object> data;
			try {
				data = JsonConvert.DeserializeObject<Dictionary<string, object>>( json );
			} catch( JsonReaderException e ) {
				result = null;
				error = "error deserializing JSON web key string";
				exception = e;
				useEncKey = false;
				return false;
			}

			if( !data.ContainsKey( "use" ) ) {
				result = null;
				error = "missing 'use' parameter in JSON web key";
				exception = null;
				useEncKey = false;
				return false;
			}

			if( data[ "use" ].ToString() != "sig" ) {
				result = null;
				error = "invalid 'use' value in JSON web key: " + data[ "use" ];
				exception = null;
				useEncKey = true;
				return false;
			}

			if( !data.ContainsKey( "kty" ) ) {
				result = null;
				error = "missing 'kty' parameter in JSON web key";
				exception = null;
				useEncKey = false;
				return false;
			}

			if( !data.ContainsKey( "kid" ) ) {
				result = null;
				error = "missing 'kid' parameter in JSON web key";
				exception = null;
				useEncKey = false;
				return false;
			}

			string id = data[ "kid" ].ToString();
			DateTime? expiresAt = null;
			if( data.ContainsKey( "exp" ) ) {
				if( !long.TryParse( data[ "exp" ].ToString(), out long ts ) ) {
					result = null;
					error = "invalid 'exp' value in JSON web key: " + data[ "exp" ];
					exception = null;
					useEncKey = false;
					return false;
				}
				expiresAt = DateTimeHelpers.FromUnixTime( ts );
			}

			switch( data[ "kty" ].ToString() ) {
				case "RSA":
					if( !data.ContainsKey( "n" ) ) {
						result = null;
						error = "missing 'n' parameter in RSA JSON web key";
						exception = null;
						useEncKey = false;
						return false;
					}

					if( !data.ContainsKey( "e" ) ) {
						result = null;
						error = "missing 'e' parameter in RSA JSON web key";
						exception = null;
						useEncKey = false;
						return false;
					}

					if( HasRsaPrivateKeyMaterial( data ) ) {
						result = null;
						error = "RSA JSON web key has private key material";
						exception = null;
						useEncKey = false;
						return false;
					}

					result = new RsaJsonWebKey(
						id: id,
						expiresAt: expiresAt,
						n: data[ "n" ].ToString(),
						e: data[ "e" ].ToString()
					);

					error = null;
					exception = null;
					useEncKey = false;

					return true;

				case "EC":
					if( !data.ContainsKey( "crv" ) ) {
						result = null;
						error = "missing 'crv' parameter in EC JSON web key";
						exception = null;
						useEncKey = false;
						return false;
					}

					if( !data.ContainsKey( "x" ) ) {
						result = null;
						error = "missing 'x' parameter in EC JSON web key";
						exception = null;
						useEncKey = false;
						return false;
					}

					if( !data.ContainsKey( "y" ) ) {
						result = null;
						error = "missing 'y' parameter in EC JSON web key";
						exception = null;
						useEncKey = false;
						return false;
					}

					result = new EcDsaJsonWebKey(
						id: id,
						expiresAt: expiresAt,
						curve: data[ "crv" ].ToString(),
						x: data[ "x" ].ToString(),
						y: data[ "y" ].ToString()
					);

					error = null;
					exception = null;
					useEncKey = false;
					return true;

				default:
					result = null;
					error = $"'{data["kty"]}' is not a supported JSON web key type";
					exception = null;
					useEncKey = false;
					return false;

			}
		}

		private static bool HasRsaPrivateKeyMaterial( IReadOnlyDictionary<string, object> data ) {
			return data.ContainsKey( "d" )
				|| data.ContainsKey( "p" )
				|| data.ContainsKey( "q" )
				|| data.ContainsKey( "dp" )
				|| data.ContainsKey( "dq" )
				|| data.ContainsKey( "qi" )
				|| data.ContainsKey( "oth" );
		}
	}

	/// <summary>
	/// Exception indicating that a JWK could not be parsed
	/// </summary>
	public class JsonWebKeyParseException : Exception {

		/// <summary>
		/// Constructs a new <see cref="JsonWebKeyParseException"/>
		/// </summary>
		public JsonWebKeyParseException( string msg ) : base( msg ) { }

		/// <summary>
		/// Constructs a new <see cref="JsonWebKeyParseException"/>
		/// </summary>
		public JsonWebKeyParseException( string msg, Exception inner ) : base( msg, inner ) { }
	}
}
