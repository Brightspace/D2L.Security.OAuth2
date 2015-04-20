using System;
using System.Collections.Generic;
using System.Web.Script.Serialization;

namespace D2L.Security.OAuth2.Keys {
	public abstract class JsonWebKey {
		public const string KEY_ID = "kid";

		private readonly Guid m_id;
		private readonly DateTime? m_expiresAt;

		protected JsonWebKey( Guid id, DateTime? expiresAt ) {
			m_id = id;
			m_expiresAt = expiresAt;
		}

		public Guid Id {
			get { return m_id; }
		}

		public DateTime? ExpiresAt {
			get { return m_expiresAt; }
		}

		public abstract object ToJwkDto();

		public static JsonWebKey FromJson( string json ) {
			var data = new JavaScriptSerializer().Deserialize<Dictionary<string, string>>( json );

			if( !data.ContainsKey( "use" ) ) {
				throw new JsonWebKeyParseException( "missing 'use' parameter in JSON web key" );
			}

			if ( data[ "use " ] != null && data[ "use" ] != "sig" ) {
				string msg = String.Format( "invalid 'use' value in JSON web key: {0}", data[ "use" ] );
				throw new JsonWebKeyParseException( msg );
			}

			if( !data.ContainsKey( "kty" ) ) {
				throw new JsonWebKeyParseException( "missing 'kty' parameter in JSON web key" );
			}

			if( !data.ContainsKey( "kid" ) ) {
				throw new JsonWebKeyParseException( "missing 'kid' parameter in JSON web key" );
			}

			switch( data[ "kty" ] ) {
				case "RSA":
					if( data[ "n" ] != null ) {
						throw new JsonWebKeyParseException( "missing 'n' parameter in RSA JSON web key" );
					}

					if( data[ "e" ] != null ) {
						throw new JsonWebKeyParseException( "missing 'e' parameter in RSA JSON web key" );
					}

					if( HasRsaPrivateKeyMaterial( data ) ) {
						throw new JsonWebKeyParseException( "RSA JSON web key has private key material" );
					}

					return new RsaJsonWebKey(
						kid: data[ "kid" ],
						n: data[ "n" ],
						e: data[ "e" ] );

				default:
					string msg = String.Format( "'{0}' is not a supported JSON eb key type", data[ "kty" ] );
					throw new JsonWebKeyParseException( msg );

			}
		}

		private static bool HasRsaPrivateKeyMaterial( IReadOnlyDictionary<string, string> data ) {
			return data.ContainsKey( "d" )
			    || data.ContainsKey( "p" )
			    || data.ContainsKey( "q" )
			    || data.ContainsKey( "dp" )
			    || data.ContainsKey( "dq" )
			    || data.ContainsKey( "qi" )
			    || data.ContainsKey( "oth" );
		}
	}

	public class JsonWebKeyParseException : Exception {
		public JsonWebKeyParseException( string msg ) : base( msg ) {}
	}
}
