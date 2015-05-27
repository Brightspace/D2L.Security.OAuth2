using System;
using System.Collections.Generic;
using System.Web.Script.Serialization;

namespace D2L.Security.OAuth2.Keys {
	
	internal class JsonWebKeySet {

		private readonly List<JsonWebKey> m_keys = new List<JsonWebKey>(); 

		public JsonWebKeySet( string json ) {
			var jss = new JavaScriptSerializer();

			try {
				var data = jss.Deserialize<Dictionary<string, List<object>>>( json );

				if( !data.ContainsKey( "keys" ) ) {
					throw new JsonWebKeyParseException( "invalid json web key set: missing keys array" );
				}

				List<object> keyObjects = data["keys"];

				foreach( object keyObject in keyObjects ) {
					string keyJson = jss.Serialize( keyObject );
					JsonWebKey key = JsonWebKey.FromJson( keyJson );
					m_keys.Add( key );
				}
			} catch( InvalidOperationException e ) {
				throw new JsonWebKeyParseException( "error parsing jwks", e );
			}

		}

		public bool TryGetKey( Guid keyId, out JsonWebKey key ) {
			foreach( JsonWebKey currentKey in m_keys ) {
				if( currentKey.Id == keyId ) {
					key = currentKey;
					return true;
				}
			}

			key = null;
			return false;
		}
	}
}
