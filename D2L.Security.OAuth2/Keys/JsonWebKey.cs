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

			if( !data.ContainsKey( "use" ) || data[ "use" ] != "sig" ) {
				throw new Exception();
			}

			if( !data.ContainsKey( "kty" ) ) {
				throw new Exception();
			}

			switch( data[ "kty" ] ) {
				case "RSA":
					return new RsaJsonWebKey(
						kid: data[ "kid" ],
						n: data[ "n" ],
						e: data[ "e" ] );

				default:
					throw new NotImplementedException();

			}
		}
	}
}
