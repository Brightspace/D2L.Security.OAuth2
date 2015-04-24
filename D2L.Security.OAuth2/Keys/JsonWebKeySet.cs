using System;
using System.Collections.Generic;
using System.Web.Script.Serialization;

namespace D2L.Security.OAuth2.Keys {
	
	internal class JsonWebKeySet {

		private readonly List<JsonWebKey> m_keys = new List<JsonWebKey>(); 

		public JsonWebKeySet( string json ) {
			var data = new JavaScriptSerializer().Deserialize<Dictionary<string, string>>( json );

			if( !data.ContainsKey( "keys" ) ) {
				throw new JsonWebKeyParseException( "invalid json web key set: missing keys array" );
			}
			
			var arrays = data["keys"];

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

		public IEnumerable<JsonWebKey> JsonWebKeys {
			get { return m_keys; }
		} 

	}
}
