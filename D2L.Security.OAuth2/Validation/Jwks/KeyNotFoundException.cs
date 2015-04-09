using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Validation.Jwks {
	public class KeyNotFoundException : Exception {

		public KeyNotFoundException( string message ) : base( message ) {}

	}
}
