using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Validation.Exceptions {
	public class PublicKeyLookupFailureException : Exception {

		public PublicKeyLookupFailureException( string message, Exception inner )
			: base( message, inner ) {}
	}
}
