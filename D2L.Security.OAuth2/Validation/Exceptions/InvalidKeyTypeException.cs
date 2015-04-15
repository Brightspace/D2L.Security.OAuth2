using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Validation.Exceptions {
	public class InvalidKeyTypeException : Exception {

		public InvalidKeyTypeException( string message ) : base( message ) {}

	}
}
