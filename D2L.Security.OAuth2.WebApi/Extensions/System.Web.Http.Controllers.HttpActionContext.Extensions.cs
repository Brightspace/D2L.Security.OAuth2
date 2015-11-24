using System;
using System.Collections.Generic;
using System.Web.Http.Controllers;

namespace D2L.Security.OAuth2 {
	internal static partial class ExtensionMethods {
		public static T GetSingleAttribute<T>( this HttpActionContext @this ) where T : class {
			var attributes = @this.ActionDescriptor.GetCustomAttributes<T>(
				inherit: false
			);

			if( attributes.Count == 0 ) {
				return null;
			}

			if( attributes.Count == 1 ) {
				return attributes[0];
			}

			throw new Exception(
				string.Format(
					"This extension method is expecting only one copy of the {0} attribute. All of its callers expect {0} to only be used once.",
					typeof( T ).FullName
				)
			);
		}
	}
}
